#!/usr/bin/env python3
"""Evidence-first Windows event review: native EVTX or OTRF/Mordor Windows log export."""
import argparse
import json
import ntpath
import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
HINT = re.compile(r"(?i)(?:^|\s)-(?:encodedcommand|enc|file|command)\s|\.ps1(?:\s|$)")

def timestamp(value, assume_utc=False):
    if not value:
        return None
    value = str(value).strip().replace(" ", "T")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        x = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if not x.tzinfo:
        if not assume_utc:
            return None
        x = x.replace(tzinfo=timezone.utc)
    return x.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def host_name(value):
    return str(value or "").split(".")[0].upper()

def as_event(raw):
    # The Windows exporter labels UtcTime as UTC. EventTime lacks timezone;
    # @timestamp is a collector clock and is never passed off as event time.
    return dict(event_id=int(raw.get("EventID") or 0),
        host=host_name(raw.get("Hostname")), provider=raw.get("SourceName") or "",
        channel=raw.get("Channel") or "", record_id=raw.get("RecordNumber"),
        time_utc=timestamp(raw.get("UtcTime"), True),
        time_local_unknown_zone=raw.get("EventTime"),
        ingestion_utc=timestamp(raw.get("@timestamp")), fields=raw)

def parse_mordor_zip(path):
    events = []
    with zipfile.ZipFile(path) as z:
        files = [x for x in z.namelist() if x.endswith(".json")]
        if not files:
            raise ValueError("No JSON event stream in the archive")
        for name in files:
            with z.open(name) as src:
                for line in src:
                    if line.strip():
                        events.append(as_event(json.loads(line)))
    return events

def parse_evtx(path):
    try:
        from Evtx.Evtx import Evtx
    except ImportError as ex:
        raise SystemExit("Install python-evtx from requirements.txt") from ex
    events = []
    with Evtx(str(path)) as archive:
        for r in archive.records():
            root = ET.fromstring(r.xml())
            s = root.find("e:System", NS)
            if s is None:
                continue
            def field(name):
                x = s.find("e:" + name, NS)
                return x.text if x is not None else None
            tc = s.find("e:TimeCreated", NS)
            provider = s.find("e:Provider", NS)
            e = dict(event_id=int(field("EventID")), host=host_name(field("Computer")),
                provider=provider.get("Name") if provider is not None else "",
                channel=field("Channel") or "",
                record_id=int(field("EventRecordID")) if field("EventRecordID") else None,
                time_utc=timestamp(tc.get("SystemTime"), True) if tc is not None else None,
                time_local_unknown_zone=None, ingestion_utc=None,
                fields={x.get("Name"): x.text for x in root.findall(".//e:EventData/e:Data", NS)
                        if x.get("Name")})
            events.append(e)
    return events

def parse_logs(path):
    if str(path).lower().endswith(".zip"):
        return parse_mordor_zip(path)
    if str(path).lower().endswith(".evtx"):
        return parse_evtx(path)
    raise ValueError("Expected .evtx or Mordor .zip")

def number(value):
    try:
        return int(str(value), 0)
    except (ValueError, TypeError):
        return None

def process(e):
    f = e["fields"]
    if e["event_id"] == 1 and "sysmon" in e["provider"].lower():
        return dict(name=ntpath.basename(f.get("Image") or "").lower(),
            image=f.get("Image"), pid=number(f.get("ProcessId")),
            ppid=number(f.get("ParentProcessId")),
            guid=str(f.get("ProcessGuid") or "").lower(),
            parent_guid=str(f.get("ParentProcessGuid") or "").lower(),
            command=f.get("CommandLine") or "")
    if e["event_id"] == 4688:
        return dict(name=ntpath.basename(f.get("NewProcessName") or "").lower(),
            image=f.get("NewProcessName"), pid=number(f.get("NewProcessId")),
            ppid=number(f.get("ProcessId")), guid="", parent_guid="",
            command=f.get("CommandLine") or "")
    return None

def boundary(e):
    # Event ID 12 is a Sysmon registry event: NEVER call it a boot.
    eid = e["event_id"]
    src = e["provider"].lower()
    chan = e["channel"].lower()
    if eid in (6005, 6006) and chan == "system" and "sysmon" not in src:
        return "Windows Event Log service start/stop"
    if eid == 12 and "kernel-general" in src:
        return "OS startup"
    if eid == 1074 and chan == "system" and ("user32" in src or not src):
        return "shutdown/restart request (not confirmed boot)"
    return None

def boundary_between(parent, child, events):
    if not parent["time_utc"] or not child["time_utc"]:
        return None
    for e in events:
        if (e["host"] == parent["host"] and boundary(e) and e["time_utc"]
                and parent["time_utc"] < e["time_utc"] < child["time_utc"]):
            return boundary(e)
    return None

def item(level, message, events=()):
    return dict(confidence=level, text=message,
        evidence=[dict(id=e["event_id"], record=e["record_id"], time_utc=e["time_utc"],
                       host=e["host"]) for e in events])

def review(events, target="WORKSTATION6"):
    target = host_name(target)
    subset = [e for e in events if e["host"] == target]
    subset.sort(key=lambda x: x["time_utc"] or x["ingestion_utc"] or "9999")
    out = dict(source_event_count=len(events), target_host=target,
        host_event_count=len(subset), confirmed=[], consistent_with=[],
        unknown=[], unsupported=[], timeline=[],
        event_counts={str(i):sum(e["event_id"] == i for e in subset)
                      for i in (1, 4624, 4688, 4104, 6005, 6006, 1074)},
        caveat="A filtered export cannot establish whether absent events were ever generated.")
    if not subset:
        out["unknown"].append(item("unknown", "No records for the selected host"))
        return out

    logons = [e for e in subset if e["event_id"] == 4624
              and str(e["fields"].get("LogonType")) == "3"]
    if logons:
        addresses = sorted(set(str(e["fields"].get("IpAddress") or "?") for e in logons))
        out["confirmed"].append(item("confirmed",
            f"{len(logons)} type-3 network logon records were observed. "
            f"Source address(es): {', '.join(addresses)}.", logons[:8]))

    script_blocks = [e for e in subset if e["event_id"] == 4104
                     and "powershell" in e["provider"].lower()]
    if script_blocks:
        out["confirmed"].append(item("confirmed",
            f"{len(script_blocks)} event 4104 PowerShell script-block record(s) exist in "
            "the host export. No process-to-script correlation is assumed.", script_blocks[:5]))

    proc_events = [(e, process(e)) for e in subset]
    proc_events = [(e, p) for e,p in proc_events if p and p["name"]]
    for child, cp in proc_events:
        # Only record actual parent names we're interested in; avoid N^2
        # unrelated legacy 4688 PID coincidences from a partial export.
        candidates = []
        for parent, pp in proc_events:
            if child is parent:
                continue
            if parent["host"] != child["host"]:
                continue
            if (parent["time_utc"] and child["time_utc"]
                    and parent["time_utc"] > child["time_utc"]):
                continue
            guid_match = bool(pp["guid"] and cp["parent_guid"]
                              and pp["guid"] == cp["parent_guid"])
            if pp["guid"] and cp["parent_guid"] and not guid_match:
                continue
            pid_match = bool(pp["pid"] is not None and cp["ppid"] is not None
                             and pp["pid"] == cp["ppid"])
            if guid_match:
                candidates.append((0, parent, pp, "guid"))
            elif (pid_match and parent["time_utc"] and child["time_utc"]):
                candidates.append((1, parent, pp, "pid"))
        if not candidates:
            continue
        candidates.sort(key=lambda c: (c[0], c[1]["time_utc"] or ""))
        _, parent, pp, method = candidates[0]
        crossing = boundary_between(parent, child, subset)
        if crossing:
            out["unknown"].append(item("unknown",
                f"Refused link {pp['name']} -> {cp['name']}; {crossing} marker is between "
                "creation events. PID reuse / restart cannot be excluded.", [parent, child]))
        elif method == "guid":
            out["confirmed"].append(item("confirmed",
                f"Sysmon recorded {cp['name']} ParentProcessGuid matching the "
                f"ProcessGuid of {pp['name']}. This documents a process-parent "
                "reference, not who initiated the action.", [parent, child]))
        else:
            out["consistent_with"].append(item("consistent_with",
                f"Parent PID of {cp['name']} matches a recorded {pp['name']} PID. "
                "No complete boot/lifecycle record: consistent with parentage, "
                "but PID reuse not excluded.", [parent, child]))

    seen_ps = set()
    for e,p in proc_events:
        if p["name"] not in ("powershell.exe", "pwsh.exe") or not HINT.search(p["command"]):
            continue
        # The same process may appear in Sysmon and 4688. This rule never
        # claims full attribution of a 4104 to a particular process.
        signature = (p["name"], p["command"])
        if signature in seen_ps:
            continue
        seen_ps.add(signature)
        if script_blocks:
            out["unknown"].append(item("unknown",
                "PowerShell launched with script-execution indicators. 4104 events "
                "exist on the host, but a specific 4104-to-process match has not "
                "been established. Payload completeness remains unknown.", [e]))
        else:
            out["unknown"].append(item("unknown",
                "Script-execution indicators appear in a PowerShell command line, "
                "but no 4104 was found in this supplied export. Whether script "
                "execution occurred and logging was configured is UNKNOWN.", [e]))

    no_command = [e for e,p in proc_events if not p["command"].strip()]
    if no_command:
        out["unknown"].append(item("unknown",
            f"{len(no_command)} process-creation entries have no command-line text. "
            "Not proof that auditing was disabled.", no_command[:5]))
    out["unknown"].append(item("unknown",
        "Host OS build and full logging/audit policy configuration are not supplied. "
        "Security EventTime is local with unverified timezone; @timestamp is "
        "collector time, not reliable proof of event creation time."))
    if logons and proc_events:
        out["consistent_with"].append(item("consistent_with",
            "Observed logons and WMI/PowerShell activity are consistent with OTRF's "
            "documented simulation of remote WMI execution, but temporal proximity "
            "alone does not prove which logon initiated which process."))
    out["unsupported"].append(item("unsupported",
        "Cannot independently claim a real-world unauthorized breach, PowerShell "
        "logging failure, erased records, or complete knowledge of the "
        "remote command's effects."))

    for e in (x for x in subset if x["event_id"] in (1,4624,4688,4104)):
        p=process(e)
        if p:
            detail = dict(process=p["name"], image=p["image"],
                          pid=p["pid"], parent_pid=p["ppid"],
                          guid=p["guid"] or None, parent_guid=p["parent_guid"] or None,
                          command_line_present=bool(p["command"]),
                          encoded_argument=bool(re.search(
                              r"(?i)\s-(?:enc|encodedcommand)\s",p["command"])))
        elif e["event_id"] == 4624:
            detail = dict(logon_type=e["fields"].get("LogonType"),
                          user=e["fields"].get("TargetUserName"),
                          source_ip=e["fields"].get("IpAddress"))
        else:
            detail = dict(script_block_present=bool(e["fields"].get("ScriptBlockText")))
        out["timeline"].append(dict(record=e["record_id"], event=e["event_id"],
            source=e["provider"], time_utc=e["time_utc"],
            local_time_unverified=e["time_local_unknown_zone"] if not e["time_utc"] else None,
            collector_utc=e["ingestion_utc"] if not e["time_utc"] else None,
            details=detail))
    return out

def render_md(out):
    lines = ["# Generated investigation findings", "",
             "Target host: " + out["target_host"],
             f"Raw events: {out['source_event_count']:,} across hosts, "
             f"{out['host_event_count']:,} from target", "",
             "## Relevant event counts", "",
             " | ".join(f"{k}: {v}" for k,v in out["event_counts"].items()), "",
             "## Event timeline (event UTC and local / collector clocks are NOT equivalent)", ""]
    for e in out["timeline"]:
        t = (e["time_utc"] + " [event UTC]" if e["time_utc"]
             else str(e["local_time_unverified"]) + " [local timezone unknown]")
        lines.append(f"- {t} | {e['event']} | record {e['record']} | "
                     + json.dumps(e["details"], ensure_ascii=False))
    for k,title in (("confirmed","Confirmed"),("consistent_with","Consistent with"),
                    ("unknown","Known unknowns"),("unsupported","Unsupported")):
        lines += ["", "## " + title, ""]
        for x in out[k]:
            ids = [str(y["record"]) for y in x["evidence"]]
            refs = (" (records " + ", ".join(ids) + ")") if ids else ""
            lines.append("- [" + x["confidence"] + "] " + x["text"] + refs)
    lines += ["", "**Caveat:** " + out["caveat"], ""]
    return "\n".join(lines)

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("logs",type=Path)
    a.add_argument("--host",default="WORKSTATION6")
    a.add_argument("--output",type=Path,default=Path("findings.md"))
    a.add_argument("--json",type=Path,default=Path("findings.json"))
    args=a.parse_args()
    result=review(parse_logs(args.logs),args.host)
    args.output.write_text(render_md(result),encoding="utf8")
    args.json.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf8")
    print(f"Analyzed {result['source_event_count']} events "
          f"({result['host_event_count']} from {result['target_host']})")
    for k in ("confirmed","consistent_with","unknown","unsupported"):
        print(f"{k}: {len(result[k])}")
    print(f"Saved {args.output} and {args.json}")
if __name__ == "__main__":
    main()

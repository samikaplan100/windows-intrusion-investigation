import unittest
from analyze import as_event, boundary, parse_logs, review

ZIP = "samples/mordor_empire_wmi.zip"

def E(eid, at, rid, *, host="WORKSTATION6", provider="Microsoft-Windows-Sysmon",
      channel="Microsoft-Windows-Sysmon/Operational", **fields):
    row = dict(EventID=eid, Hostname=host, SourceName=provider,
               Channel=channel, UtcTime=at, RecordNumber=rid)
    row.update(fields)
    return as_event(row)

def proc(at,rid,name,pid=None,ppid=None,guid=None,parent_guid=None,cmd=""):
    f = dict(Image=r"C:\Windows\System32\\"+name, CommandLine=cmd)
    if pid is not None: f["ProcessId"] = str(pid)
    if ppid is not None: f["ParentProcessId"] = str(ppid)
    if guid is not None: f["ProcessGuid"] = guid
    if parent_guid is not None: f["ParentProcessGuid"] = parent_guid
    return E(1,at,rid,**f)

class TestRealDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = parse_logs(ZIP)
        cls.result = review(cls.raw, "WORKSTATION6")

    def test_dataset_is_larger_and_pinned(self):
        self.assertEqual(len(self.raw), 6383)
        self.assertEqual(self.result["host_event_count"], 1871)

    def test_actual_event_inventory(self):
        c = self.result["event_counts"]
        self.assertEqual(c["1"],4)
        self.assertEqual(c["4624"],4)
        self.assertEqual(c["4688"],4)
        self.assertEqual(c["4104"],1)

    def test_real_sysmon_wmi_powershell_whoami_parent_guids(self):
        reports = " ".join(x["text"].lower() for x in self.result["confirmed"])
        self.assertIn("powershell.exe", reports)
        self.assertIn("wmiprvse.exe", reports)
        self.assertIn("whoami.exe", reports)
        self.assertIn("parentprocessguid", reports)

    def test_real_4104_is_not_invented_gap(self):
        evidence = " ".join(x["text"] for x in self.result["confirmed"])
        self.assertIn("4104",evidence)
        self.assertFalse(any("no 4104" in x["text"].lower() for x in self.result["unknown"]))
        self.assertFalse(any("disabled" in x["text"].lower() for x in self.result["confirmed"]))

    def test_local_security_clock_is_not_invented_utc(self):
        logon=next(x for x in self.result["timeline"] if x["event"] == 4624)
        self.assertIsNone(logon["time_utc"])
        self.assertEqual(logon["local_time_unverified"],"2020-09-21 00:14:53")

    def test_json_confidence_fields_present(self):
        for category in ("confirmed","consistent_with","unknown","unsupported"):
            self.assertTrue(self.result[category])
            self.assertTrue(all(f["confidence"] == category for f in self.result[category]))

    def test_original_native_evtx_parser_remains_available(self):
        legacy = parse_logs("archive/initial-eight-event-case/wmi_target.evtx")
        self.assertEqual(len(legacy),8)
        self.assertEqual(sum(x["event_id"] == 4688 for x in legacy),2)

class TestRebootAndPidReuse(unittest.TestCase):
    def setUp(self):
        self.parent = proc("2020-01-01T10:00:00Z",101,
                           "WmiPrvSE.exe",pid=2740,cmd="wmiprvse.exe")
        self.child = proc("2020-01-01T10:00:20Z",102,
                          "powershell.exe",pid=9804,ppid=2740,cmd="powershell.exe")
        self.boot = E(6005,"2020-01-01T10:00:10Z",103,
                      provider="EventLog",channel="System")

    def test_pid_reuse_across_reboot_refuses_link(self):
        r=review([self.parent,self.boot,self.child])
        self.assertTrue(any("Refused link" in x["text"] for x in r["unknown"]))
        self.assertFalse(any("Parent PID" in x["text"] for x in r["consistent_with"]))
        self.assertFalse(any("ParentProcessGuid" in x["text"] for x in r["confirmed"]))

    def test_no_boot_markers_must_downgrade_pid_only_link(self):
        r=review([self.parent,self.child])
        self.assertTrue(any("PID reuse not excluded" in x["text"] for x in r["consistent_with"]))
        self.assertFalse(any("Parent PID" in x["text"] for x in r["confirmed"]))

    def test_sysmon_event_12_is_not_a_boot_marker(self):
        registry = E(12,"2020-01-01T10:00:10Z",111,
                     Image="C:\\Windows\\reg.exe")
        self.assertIsNone(boundary(registry))
        r=review([self.parent,registry,self.child])
        self.assertTrue(any("PID reuse not excluded" in x["text"] for x in r["consistent_with"]))

    def test_shutdown_request_1074_is_not_accepted_as_completed_reboot(self):
        shutdown=E(1074,"2020-01-01T10:00:10Z",104,
                   provider="User32",channel="System")
        r=review([self.parent,shutdown,self.child])
        self.assertTrue(any("request" in x["text"].lower() for x in r["unknown"]))
        self.assertFalse(any("Parent PID" in x["text"] for x in r["consistent_with"]))

    def test_guid_match_is_confirmed_recorded_reference(self):
        parent=proc("2020-01-01T10:00:00Z",101,
                    "WmiPrvSE.exe",guid="{parent}",pid=2740)
        child=proc("2020-01-01T10:00:20Z",102,
                   "powershell.exe",guid="{child}",parent_guid="{parent}",ppid=2740)
        r=review([parent,child])
        self.assertTrue(any("ParentProcessGuid" in x["text"] for x in r["confirmed"]))

    def test_guid_reuse_across_reboot_is_refused(self):
        parent=proc("2020-01-01T10:00:00Z",101,
                    "WmiPrvSE.exe",guid="{same}",pid=2740)
        child=proc("2020-01-01T10:00:20Z",102,
                   "powershell.exe",guid="{other}",parent_guid="{same}",ppid=2740)
        r=review([parent,self.boot,child])
        self.assertTrue(any("Refused link" in x["text"] for x in r["unknown"]))
        self.assertFalse(any("ParentProcessGuid" in x["text"] for x in r["confirmed"]))

    def test_mismatched_guids_cannot_fallback_to_matching_pid(self):
        parent=proc("2020-01-01T10:00:00Z",101,
                    "WmiPrvSE.exe",guid="{old}",pid=2740)
        child=proc("2020-01-01T10:00:20Z",102,
                   "powershell.exe",guid="{new}",parent_guid="{different}",ppid=2740)
        r=review([parent,child])
        self.assertFalse(any("Parent PID" in x["text"] for x in r["consistent_with"]))
        self.assertFalse(any("ParentProcessGuid" in x["text"] for x in r["confirmed"]))

    def test_mismatched_hosts_never_link(self):
        child=proc("2020-01-01T10:00:20Z",102,
                   "powershell.exe",ppid=2740)
        other=proc("2020-01-01T10:00:00Z",101,
                   "WmiPrvSE.exe",pid=2740)
        other["host"]="OTHER-PC"
        r=review([other,child])
        self.assertFalse(r["consistent_with"])

    def test_child_before_parent_cannot_link(self):
        child=proc("2020-01-01T09:00:00Z",102,
                   "powershell.exe",ppid=2740)
        r=review([self.parent,child])
        self.assertFalse(any("Parent PID" in x["text"] for x in r["consistent_with"]))

class TestPowerShellClaims(unittest.TestCase):
    def test_bare_powershell_is_not_a_missing_script_block_gap(self):
        e=proc("2020-01-01T10:00:00Z",101,"powershell.exe",
               cmd="powershell.exe")
        r=review([e])
        self.assertFalse(any("4104" in x["text"] for x in r["unknown"]))

    def test_script_hint_with_no_4104_is_unknown_not_confirmed(self):
        e=proc("2020-01-01T10:00:00Z",101,"powershell.exe",
               cmd="powershell.exe -File C:\\Temp\\test.ps1")
        r=review([e])
        self.assertTrue(any("no 4104" in x["text"].lower() for x in r["unknown"]))
        self.assertFalse(any("logging" in x["text"].lower() for x in r["confirmed"]))

    def test_script_block_present_does_not_equal_correlated(self):
        e=proc("2020-01-01T10:00:00Z",101,"powershell.exe",
               cmd="powershell.exe -Command Write-Host test")
        ps=E(4104,"2020-01-01T10:00:03Z",102,
             provider="Microsoft-Windows-PowerShell",channel="Microsoft-Windows-PowerShell/Operational",
             ScriptBlockText="Write-Host test")
        r=review([e,ps])
        self.assertTrue(any("not been established" in x["text"] for x in r["unknown"]))
        self.assertTrue(any("4104" in x["text"] for x in r["confirmed"]))

if __name__ == "__main__":
    unittest.main(verbosity=2)

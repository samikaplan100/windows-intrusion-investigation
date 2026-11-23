# Incident investigation — WMI remote execution (historical Mordor lab)

**Status:** Completed manual review against a 6,383-record public Windows event export; process correlations evaluated conservatively. This is an authorized historical attack simulation, not a real victim intrusion.

**Central question:** What evidence supports the source author's simulated WMI remote execution, and what cannot be attributed with confidence?

## Provenance and scenario
See dataset_provenance.md for pinned source commit, 2 SHA-256 hashes, capture date, per-host record counts, license, and known/unknown OS and logging configuration. OTRF dataset SDWIN-200921001437 is titled *Empire Invoke WMI*. The publisher's adversary-side notes describe sending an Empire Invoke-WMI stager from WORKSTATION5 to WORKSTATION6 and then running whoami on the target. These notes provide scenario ground truth; our conclusions from host events must be kept separate.

## Scope / clock
- 6,383 events in the original host ZIP across multiple systems; target WORKSTATION6 = 1,871 records (including FQDN/short-name normalization).
- Sysmon UtcTime is explicitly UTC. Security and PowerShell EventTime uses local time with an unverified timezone; the collector @timestamp is not a substitute for the underlying event UTC clock.
- The **UTC timeline below uses only Sysmon event creation times**. The adjacent Security/PowerShell records are discussed separately using their original local-time strings.

## Confirmed event timeline (Sysmon UTC)
| Timestamp (UTC) | Event | Observed fact | Event record |
| --- | --- | --- | --- |
| 2020-09-21 04:14:53.715 | Sysmon 1 | WmiPrvSE.exe process creation; ProcessGuid ending ae08 | 3215112 |
| 2020-09-21 04:14:53.831 | Sysmon 1 | powershell.exe launched with a long encoded-command argument; ParentProcessGuid matches WmiPrvSE.exe ProcessGuid | 3215160 |
| 2020-09-21 04:14:53.846 | Sysmon 1 | conhost.exe process creation; ParentProcessGuid matches powershell.exe ProcessGuid | 3215167 |
| 2020-09-21 04:15:12.964 | Sysmon 1 | whoami.exe process creation; ParentProcessGuid matches powershell.exe ProcessGuid | 3215794 |

**Direct observation:** the recorded process tree WmiPrvSE.exe -> powershell.exe -> whoami.exe is supported by exact Sysmon GUID references. This is stronger than bare matching PIDs, although the record alone cannot establish the operator's intent or who initiated the WMI operation.

## Corroborating host events (source's local EventTime; timezone unverified)
- 2020-09-21 00:14:53: four type-3 network logon records (4624) for pgustavo, source 172.18.39.5; record numbers 768442, 768447, 768450, 768453.
- 2020-09-21 00:14:53: Security 4688 process-creation records for WmiPrvSE.exe, powershell.exe and conhost.exe. Command-line fields are populated (record numbers 768458, 768477, 768478).
- 2020-09-21 00:14:55: one PowerShell Script Block Logging 4104 event is present (record 8669).
- 2020-09-21 00:15:12: a 4688 whoami.exe event is present (record 768702).
- There are 108 Event 4103 PowerShell module-logging records in the target export.

Do **not** treat the source's local EventTime values as independently verified UTC, and do **not** assert the 4104 belongs to a specific PowerShell process without further linkage.

## Confirmed
1. Network logon events were recorded for the target host from 172.18.39.5.
2. Sysmon recorded a WMI provider spawning PowerShell and PowerShell spawning whoami.exe by parent GUID references.
3. The PowerShell process command-line argument contains an encoded-command indicator. The command line itself is available in the raw dataset; we do not infer its complete effects solely from the flag.
4. A PowerShell 4104 script-block record exists. Script-block telemetry is present in this export; full coverage and process-level attribution remain unverified.

## Consistent with, not independently proven
- The combined record pattern supports the publisher's documented Empire WMI remote-execution simulation (ATT&CK T1047).
- The network logons near the process tree are consistent with remote execution. The logs examined do not independently demonstrate which precise logon spawned the process, which person controlled the credentials, or whether the activity was unauthorized outside this known lab.

## Known unknowns
- Was Script Block Logging enabled by policy during the full timeframe? **UNKNOWN**. One 4104 exists, but detailed policy state and full collection coverage are unknown.
- Were all Security, PowerShell, WMI Activity and Sysmon events preserved? **UNKNOWN**. This is a curated export.
- Which OS build and patch level generated the events? **UNKNOWN**.
- What exact timezone converts the source's local Security EventTime to UTC? **UNKNOWN** from event fields; no invented offset.
- Whether boot/shutdown occurred outside the curated window, and complete PID lifecycle: **UNKNOWN**. There are zero System 6005, 6006 and 1074 markers in the supplied target export. Their absence cannot establish uninterrupted uptime.
- Does the observed 4104 necessarily describe the same PowerShell process? **UNVERIFIED** without stronger correlation.
- How much of the execution payload completed, what remote actions succeeded, and whether persistence was established: **UNVERIFIED** from this limited review.

## PID correlation caveats (including reboot)
- Windows PIDs can be reused after process exit and reboot. Temporal order alone does not eliminate reuse.
- **Prefer Sysmon ProcessGuid/ParentProcessGuid** when both sides are present. This dataset contains such references for the key process chain.
- **PID-only parent matches are merely CONSISTENT_WITH**, not confirmed, if we cannot verify a complete boot/process-lifecycle history. The analyzer implements this downgrade.
- The analyzer treats a timed System EventLog 6005/6006 or Kernel-General startup event 12 between a parent and child as a boundary warning and refuses the PID link. A System/User32 1074 is only a *shutdown/restart request*, not proof of a completed reboot; it still triggers a conservative refusal.
- A **Sysmon ID 12 is a registry event**, not a Windows boot marker. It must not be confused with Kernel-General ID 12.
- An event has to be time-comparable (verified UTC) to act as a cross-source boundary. If a System log offers only unspecified local time, the tool cannot infer the absolute boundary.
- No recorded boot marker does **not** prove there was no boot.

## Unsupported conclusions
- A malicious real-world breach occurred.
- The source address directly caused the PowerShell process, without case-specific correlation.
- PowerShell Script Block Logging was disabled. A 4104 event is present, while the policy configuration remains unknown.
- A gap in EventRecordID sequence proves event deletion. This is a filtered dataset.
- The PowerShell payload was fully reconstructed or every command executed successfully.

## Investigative next requests
Recheck detailed Security 4624 Logon IDs and 4688 contexts, WMI-Activity operational events, PowerShell 4103/4104 content (without executing it), and process token/logon context. Retrieve the original OTRF adversary-side Empire Invoke-WMI log (source-side stager output), if publicly available, and compare it to the host-side process tree to evaluate attribution independently. Request an actual audit-policy export and OS build if one is available; otherwise document Unknown. Compare Sysmon process GUIDs across channels and validate event clock normalization before making stronger attribution.

## Conclusion
**Defensible finding:** this documented lab dataset contains a WMI-provider process chain into PowerShell and whoami.exe, plus corroborating network logons and PowerShell telemetry. That is persuasive evidence for the *documented simulated technique*. It does not independently prove unauthorized intent or complete payload effects.

The detection script is a small evidence categorizer. Its job is to reflect these limitations, not to invent an incident, a logging failure or deleted telemetry.

# Dataset provenance — OTRF/Mordor Empire Invoke WMI

## Source and custody
- Project: OTRF/Security-Datasets, Mordor (MIT-licensed)
- Dataset identifier: SDWIN-200921001437
- Dataset title: Empire Invoke WMI
- Upstream repository: https://github.com/OTRF/Security-Datasets
- Pinned upstream commit: d9d40ef123d2c87d5d3df28c96bcab4f0faccc87 (commit date 2023-09-20; this is not the incident date)
- Scenario metadata: https://raw.githubusercontent.com/OTRF/Security-Datasets/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/_metadata/SDWIN-200921001437.yaml
- ZIP source: https://raw.githubusercontent.com/OTRF/Security-Datasets/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip
- Local archive: samples/mordor_empire_wmi.zip
- SHA-256 of original ZIP: 96f1dbd9c5b077c8951b6e1f43b7fe01a2620c649889262481f15139a1746d88
- Inner file: empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod_2020-09-21001437.json
- SHA-256 of inner uncompressed JSON event stream: b796a97fac2b94e03cce777b88960d227c1ae5e4ce4824f2f1540b28ff3479f3
- Download verification: source ZIP hash calculated after fetching; original archive stored unchanged.
- Capture scenario recorded in metadata: creation_date 2020/09/21, modification_date 2020/09/22.
- OS build: UNKNOWN. No original Windows build identifier is established by the metadata or inspected process events.
- Raw data format: exported real Windows event records as NDJSON inside ZIP. NOT an original native .evtx capture. The analyzer retains a separate native EVTX parser.

## Simulated action / ground truth
The OTRF metadata describes an authorized attack simulation in the Mordor Shire lab using Empire's Invoke-WMI lateral movement module (MITRE ATT&CK T1047). Its adversary-side notes record a source agent on WORKSTATION5, target WORKSTATION6.theshire.local, a new target agent checking in, and a subsequent whoami command. Those adversary notes are the *simulation's declared ground truth*, not observations independently proved by the host event records.

## Scope and target
- Full host ZIP: 6,383 exported event records.
- Selected target: WORKSTATION6, including 1716 records using the FQDN form and 155 using the short hostname, normalized to WORKSTATION6 (1,871).
- Other hosts include WORKSTATION5 and MORDORDC; their events are counted as source context but are not silently merged into the target timeline.
- Collection time: observed target records cover 21 Sep 2020 around 04:14-04:15 UTC for Sysmon UtcTime.
- Windows Security/PowerShell EventTime is local with no explicit timezone in the fields; its mapping to UTC is NOT independently established. Collector @timestamp is explicitly *ingestion time*, not event-creation time.
- Hostname normalization assumes WORKSTATION6 and WORKSTATION6.theshire.local refer to the same lab system. This is reasonable in the named lab, but it is still an assumption. Do not generalize this for arbitrary company datasets.

## Verified event visibility, not inferred audit configuration
- Sysmon Event 1 process creation: 4 on the target; ProcessGuid and ParentProcessGuid present in these records.
- Windows Security Event 4688: 4 on the target, with command-line strings present.
- Windows Security Event 4624: 4 type-3 network-logon records from 172.18.39.5 associated with pgustavo on the target.
- Windows PowerShell Event 4104: 1 script-block record on the target.
- PowerShell module logging Event 4103: 108 target records.
- System Event 6005/6006/1074 boot/shutdown markers: 0 in the supplied target export. **This is not proof that no reboot happened.**
- Sysmon Event 12 appears many times and relates to registry object creation/deletion, **not** reboot; our reboot check excludes it.

## Config values unknown
- Audit policy and whether it was enabled continuously: UNKNOWN. The presence of 4624/4688 establishes observed events, not policy history.
- Exact settings of Script Block Logging, transcript logging and other PowerShell policy/registry values: UNKNOWN. Event 4104 proves at least one block event was emitted, not comprehensive collection.
- Sysmon config and full channel coverage: UNKNOWN.
- Whether all host events from the incident period were exported: UNKNOWN.
- Independent OS build / patch level: UNKNOWN.
- Full boot and PID lifecycle history: UNKNOWN.

## Integrity and publication notes
- Use raw source links and the hashes above for external independent verification.
- ZIP contents are historical lab security telemetry, not information from a live victim.
- Strong process evidence comes from actual Sysmon ProcessGuid/ParentProcessGuid references, not from an unsupported claim that PID reuse was impossible.
- Only use precise UTC event timestamps for cross-event timestamp-based process correlation. System logs with unverified local time cannot verify a reboot boundary on a UTC timeline unless normalized with evidence.
- An absent log entry is not proof that logging was disabled, that an event was deleted, or that an attack did not occur.
- Review the dataset and its MIT licence before redistributing the archive publicly.

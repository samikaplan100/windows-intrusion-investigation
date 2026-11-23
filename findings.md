# Generated investigation findings

Target host: WORKSTATION6
Raw events: 6,383 across hosts, 1,871 from target

## Relevant event counts

1: 4 | 4624: 4 | 4688: 4 | 4104: 1 | 6005: 0 | 6006: 0 | 1074: 0

## Event timeline (event UTC and local / collector clocks are NOT equivalent)

- 2020-09-21T04:14:53.715000Z [event UTC] | 1 | record 3215112 | {"process": "wmiprvse.exe", "image": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "pid": null, "parent_pid": 960, "guid": "{d273d0f0-28bd-5f68-ae08-000000000800}", "parent_guid": "{d273d0f0-e866-5f64-1100-000000000800}", "command_line_present": true, "encoded_argument": false}
- 2020-09-21T04:14:53.831000Z [event UTC] | 1 | record 3215160 | {"process": "powershell.exe", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": null, "parent_pid": 2740, "guid": "{d273d0f0-28bd-5f68-af08-000000000800}", "parent_guid": "{d273d0f0-28bd-5f68-ae08-000000000800}", "command_line_present": true, "encoded_argument": true}
- 2020-09-21T04:14:53.846000Z [event UTC] | 1 | record 3215167 | {"process": "conhost.exe", "image": "C:\\Windows\\System32\\conhost.exe", "pid": null, "parent_pid": 9804, "guid": "{d273d0f0-28bd-5f68-b008-000000000800}", "parent_guid": "{d273d0f0-28bd-5f68-af08-000000000800}", "command_line_present": true, "encoded_argument": false}
- 2020-09-21 00:14:53 [local timezone unknown] | 4624 | record 768442 | {"logon_type": "3", "user": "pgustavo", "source_ip": "172.18.39.5"}
- 2020-09-21 00:14:53 [local timezone unknown] | 4624 | record 768447 | {"logon_type": "3", "user": "pgustavo", "source_ip": "172.18.39.5"}
- 2020-09-21 00:14:53 [local timezone unknown] | 4624 | record 768450 | {"logon_type": "3", "user": "pgustavo", "source_ip": "172.18.39.5"}
- 2020-09-21 00:14:53 [local timezone unknown] | 4624 | record 768453 | {"logon_type": "3", "user": "pgustavo", "source_ip": "172.18.39.5"}
- 2020-09-21 00:14:53 [local timezone unknown] | 4688 | record 768458 | {"process": "wmiprvse.exe", "image": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "pid": 2740, "parent_pid": 960, "guid": null, "parent_guid": null, "command_line_present": true, "encoded_argument": false}
- 2020-09-21 00:14:53 [local timezone unknown] | 4688 | record 768477 | {"process": "powershell.exe", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 9804, "parent_pid": 2740, "guid": null, "parent_guid": null, "command_line_present": true, "encoded_argument": true}
- 2020-09-21 00:14:53 [local timezone unknown] | 4688 | record 768478 | {"process": "conhost.exe", "image": "C:\\Windows\\System32\\conhost.exe", "pid": 8204, "parent_pid": 9804, "guid": null, "parent_guid": null, "command_line_present": true, "encoded_argument": false}
- 2020-09-21 00:14:55 [local timezone unknown] | 4104 | record 8669 | {"script_block_present": true}
- 2020-09-21T04:15:12.964000Z [event UTC] | 1 | record 3215794 | {"process": "whoami.exe", "image": "C:\\Windows\\System32\\whoami.exe", "pid": null, "parent_pid": 9804, "guid": "{d273d0f0-28d0-5f68-b108-000000000800}", "parent_guid": "{d273d0f0-28bd-5f68-af08-000000000800}", "command_line_present": true, "encoded_argument": false}
- 2020-09-21 00:15:12 [local timezone unknown] | 4688 | record 768702 | {"process": "whoami.exe", "image": "C:\\Windows\\System32\\whoami.exe", "pid": 2044, "parent_pid": 9804, "guid": null, "parent_guid": null, "command_line_present": true, "encoded_argument": false}

## Confirmed

- [confirmed] 4 type-3 network logon records were observed. Source address(es): 172.18.39.5. (records 768442, 768447, 768450, 768453)
- [confirmed] 1 event 4104 PowerShell script-block record(s) exist in the host export. No process-to-script correlation is assumed. (records 8669)
- [confirmed] Sysmon recorded powershell.exe ParentProcessGuid matching the ProcessGuid of wmiprvse.exe. This documents a process-parent reference, not who initiated the action. (records 3215112, 3215160)
- [confirmed] Sysmon recorded conhost.exe ParentProcessGuid matching the ProcessGuid of powershell.exe. This documents a process-parent reference, not who initiated the action. (records 3215160, 3215167)
- [confirmed] Sysmon recorded whoami.exe ParentProcessGuid matching the ProcessGuid of powershell.exe. This documents a process-parent reference, not who initiated the action. (records 3215160, 3215794)

## Consistent with

- [consistent_with] Observed logons and WMI/PowerShell activity are consistent with OTRF's documented simulation of remote WMI execution, but temporal proximity alone does not prove which logon initiated which process.

## Known unknowns

- [unknown] PowerShell launched with script-execution indicators. 4104 events exist on the host, but a specific 4104-to-process match has not been established. Payload completeness remains unknown. (records 3215160)
- [unknown] Host OS build and full logging/audit policy configuration are not supplied. Security EventTime is local with unverified timezone; @timestamp is collector time, not reliable proof of event creation time.

## Unsupported

- [unsupported] Cannot independently claim a real-world unauthorized breach, PowerShell logging failure, erased records, or complete knowledge of the remote command's effects.

**Caveat:** A filtered export cannot establish whether absent events were ever generated.

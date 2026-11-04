---
id: H02
title: LSASS memory access to steal credentials
techniques: [T1003.001]
tactics: [credential-access]
platforms: [windows]
data_sources:
  - Sysmon EID 10 (ProcessAccess)
  - Sysmon EID 1 (process creation)
  - Sysmon EID 11 (file creation)
index: wazuh-archives-*
emulation: [EMU-02]
---

# H02 · LSASS memory access

## Hypothesis

An attacker with administrator privileges dumps the memory of `lsass.exe`
(comsvcs.dll MiniDump, ProcDump, Mimikatz, nanodump...) to extract hashes and
Kerberos tickets.

## Question

Which processes outside the list of known system processes have opened
`lsass.exe` with memory read permissions, which command lines use
`comsvcs.dll` + `MiniDump`, and where have lsass `.dmp` files been written?

## Data required

- **Sysmon EID 10** with a `ProcessAccess` rule that includes `TargetImage` lsass.exe
  (sysmon-modular and the SwiftOnSecurity configuration ship it): `sourceImage`,
  `targetImage`, `grantedAccess`, `callTrace`.
- **Sysmon EID 1**: `commandLine` of `rundll32.exe`, `procdump*.exe`...
- **Sysmon EID 11**: `targetFilename` of the dumps.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
(data.win.system.eventID:10 and data.win.eventdata.targetImage:*\\lsass.exe and not data.win.eventdata.sourceImage:(*\\MsMpEng.exe or *\\wininit.exe or *\\csrss.exe)) or (data.win.system.eventID:1 and data.win.eventdata.commandLine:*comsvcs* and data.win.eventdata.commandLine:*MiniDump*)
```

### OpenSearch Query DSL

```json
{
  "size": 100,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.eventdata.sourceImage", "data.win.eventdata.targetImage", "data.win.eventdata.grantedAccess", "data.win.eventdata.callTrace", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.targetFilename", "data.win.eventdata.user"],
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-7d"}}},
        {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}}
      ],
      "should": [
        {"bool": {
          "filter": [
            {"term": {"data.win.system.eventID": "10"}},
            {"wildcard": {"data.win.eventdata.targetImage": {"value": "*\\\\lsass.exe", "case_insensitive": true}}},
            {"terms": {"data.win.eventdata.grantedAccess": ["0x1010", "0x1410", "0x1438", "0x143A", "0x143a", "0x1FFFFF", "0x1fffff", "0x1F0FFF", "0x1f0fff", "0x1F1FFF", "0x1f1fff", "0x1F3FFF", "0x1f3fff", "0x40"]}}
          ],
          "must_not": [
            {"wildcard": {"data.win.eventdata.sourceImage": {"value": "*\\\\msmpeng.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.sourceImage": {"value": "*\\\\wininit.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.sourceImage": {"value": "*\\\\csrss.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.sourceImage": {"value": "*\\\\wmiprvse.exe", "case_insensitive": true}}}
          ]
        }},
        {"bool": {"filter": [
          {"term": {"data.win.system.eventID": "1"}},
          {"wildcard": {"data.win.eventdata.commandLine": {"value": "*comsvcs*", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.commandLine": {"value": "*minidump*", "case_insensitive": true}}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.eventID": "11"}},
          {"wildcard": {"data.win.eventdata.targetFilename": {"value": "*lsass*.dmp", "case_insensitive": true}}}
        ]}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

## Interpretation

- **What is suspicious**: `rundll32.exe`, `powershell.exe`, `procdump*.exe`,
  `taskmgr.exe` or binaries in `%TEMP%`/`C:\Users\` opening lsass with `0x1FFFFF`,
  `0x1410` or `0x1010`; `callTrace` with `dbghelp.dll`/`dbgcore.dll` (MiniDumpWriteDump)
  or with `UNKNOWN(...)` (injected code); any lsass `.dmp` outside an
  authorized investigation.
- **Common false positives**: antivirus/EDR, backup agents and monitoring
  tools that query lsass with `0x1410`. Add them to the `must_not` after
  verifying signature and path.
- **Next steps**: review the later logons of the accounts that
  were in memory (H09), look for Pass-the-Hash (4624 logonType 9 / NTLM from
  unusual hosts) and exfiltration of the `.dmp`.
- **If nothing shows up**: run EMU-02. If Sysmon does not log EID 10 for lsass, the
  Sysmon configuration lacks the ProcessAccess rule.

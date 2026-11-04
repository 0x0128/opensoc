---
id: H05
title: New Windows services with binaries in writable paths
techniques: [T1543.003]
tactics: [persistence, privilege-escalation]
platforms: [windows]
data_sources:
  - System EID 7045 (service installed)
  - Security EID 4697 (service installed, System Extension auditing)
  - Sysmon EID 1 (sc.exe create)
index: wazuh-archives-*
emulation: []
---

# H05 · New services with binaries in writable paths

## Hypothesis

An attacker installs a service (PsExec, Impacket `smbexec`/`services.py`, Cobalt
Strike `jump psexec`, or a custom service) whose binary lives in a user-writable path
or whose `ImagePath` is directly a command line.

## Question

Which services have been installed in the last 30 days whose `ImagePath` is in
`\Users\`, `\Temp\`, `\AppData\`, `\ProgramData\`, `\PerfLogs\`, or runs `cmd /c`,
`powershell` or `%COMSPEC%`? On how many hosts does the same service name appear?

## Data required

- **System 7045** (on by default in Windows): `data.win.eventdata.serviceName`,
  `imagePath`, `serviceType`, `startType`, `accountName`.
- **Security 4697** (auditing *System → Security System Extension*):
  `data.win.eventdata.serviceFileName`, `subjectUserName`.
- **Sysmon EID 1** of `sc.exe create` to know who created it.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:(7045 or 4697) and (data.win.eventdata.imagePath:(*\\Users\\* or *\\Temp\\* or *\\AppData\\* or *\\ProgramData\\* or *cmd* or *powershell* or *COMSPEC*) or data.win.eventdata.serviceFileName:(*\\Users\\* or *\\Temp\\* or *cmd* or *powershell*))
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.eventdata.serviceName", "data.win.eventdata.imagePath", "data.win.eventdata.serviceFileName", "data.win.eventdata.accountName", "data.win.eventdata.startType", "data.win.eventdata.subjectUserName"],
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-30d"}}},
        {"terms": {"data.win.system.eventID": ["7045", "4697"]}}
      ],
      "should": [
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*\\\\users\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*\\\\temp\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*\\\\appdata\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*\\\\programdata\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*\\\\perflogs\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*cmd*/c*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*powershell*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.imagePath": {"value": "*%comspec%*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.serviceFileName": {"value": "*\\\\users\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.serviceFileName": {"value": "*\\\\temp\\\\*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.serviceFileName": {"value": "*cmd*/c*", "case_insensitive": true}}},
        {"wildcard": {"data.win.eventdata.serviceFileName": {"value": "*powershell*", "case_insensitive": true}}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_service": {
      "terms": {"field": "data.win.eventdata.serviceName", "size": 30},
      "aggs": {"hosts": {"cardinality": {"field": "agent.name"}}}
    }
  }
}
```

## Interpretation

- **What is suspicious**: random 4-8 character names (the pattern of Impacket and
  renamed PsExec), `PSEXESVC` on hosts where PsExec is not used, an `ImagePath` with
  `cmd.exe /Q /c echo ... > \\127.0.0.1\C$\__output` (smbexec), binaries in
  `\Windows\Temp\` or `ADMIN$`, *auto* `startType` services with the LocalSystem account
  created outside a change window.
- **Common false positives**: software and driver installers, inventory/EDR
  agents (sometimes in `\ProgramData\`), authorized remote administration
  tools. The `hosts` field of the aggregation helps: a legitimate service is usually
  present on many hosts; a malicious one, on few.
- **Next steps**: correlate with the preceding type 3 4624 on that host to
  know where it was installed from (H09), and with Sysmon EID 1 whose `parentImage` is
  `services.exe` to see what it ran.
- **Validation**: there is no scenario in `emulation/scenarios.yaml`; you can run
  `Invoke-AtomicTest T1543.003` by hand in the lab.

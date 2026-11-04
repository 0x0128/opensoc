---
id: H03
title: Persistence in Run/RunOnce and Winlogon keys
techniques: [T1547.001]
tactics: [persistence, privilege-escalation]
platforms: [windows]
data_sources:
  - Sysmon EID 12/13 (registry)
  - Wazuh registry FIM (syscheck, windows_registry)
index: wazuh-archives-*
emulation: [EMU-04]
---

# H03 · Persistence in Run/RunOnce and Winlogon keys

## Hypothesis

An attacker sets up persistence by writing a value in
`...\CurrentVersion\Run`, `RunOnce`, `Policies\Explorer\Run` or in `Winlogon\Userinit`
/ `Winlogon\Shell` so that their binary starts at every logon.

## Question

Which values have been created or modified in the autostart keys in the
last 30 days, by which process, and which executable do they point to?

## Data required

- **Sysmon EID 13** (RegistryEvent Value Set) and **EID 12** (key creation):
  `data.win.eventdata.targetObject`, `details` (data written), `image` (writing
  process), `user`. It is the only source that covers **HKCU** (HKU\SID\...).
- **Wazuh registry FIM**: by default the Windows agent monitors
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`. Fields
  `syscheck.path`, `syscheck.value_name`, `syscheck.event`.
- `wazuh-archives-*` index for Sysmon (the FIM events are also in
  `wazuh-alerts-*`).

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
(data.win.system.eventID:(12 or 13) and data.win.eventdata.targetObject:(*\\CurrentVersion\\Run* or *\\Policies\\Explorer\\Run* or *\\Winlogon\\Userinit* or *\\Winlogon\\Shell*)) or syscheck.path:*CurrentVersion\\Run*
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.eventdata.image", "data.win.eventdata.targetObject", "data.win.eventdata.details", "data.win.eventdata.user", "syscheck.path", "syscheck.value_name", "syscheck.event"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}],
      "should": [
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
          {"terms": {"data.win.system.eventID": ["12", "13"]}},
          {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.targetObject": {"value": "*\\\\currentversion\\\\run*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.targetObject": {"value": "*\\\\policies\\\\explorer\\\\run*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.targetObject": {"value": "*\\\\winlogon\\\\userinit", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.targetObject": {"value": "*\\\\winlogon\\\\shell", "case_insensitive": true}}}
          ], "minimum_should_match": 1}}
        ]}},
        {"wildcard": {"syscheck.path": {"value": "*\\\\currentversion\\\\run*", "case_insensitive": true}}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_process": {"terms": {"field": "data.win.eventdata.image", "size": 20}},
    "by_value": {"terms": {"field": "data.win.eventdata.details", "size": 20}}
  }
}
```

## Interpretation

- **What is suspicious**: `details` pointing to `%APPDATA%`, `%TEMP%`, `C:\Users\Public`,
  `C:\ProgramData` or to LOLBins (`rundll32`, `mshta`, `powershell -enc`, `wscript`);
  values written by `reg.exe`, `powershell.exe` or unsigned processes; names that
  imitate legitimate software ("OneDrive Update", "Windows Defender"); changes to
  `Winlogon\Userinit` other than `C:\Windows\system32\userinit.exe,`.
- **Common false positives**: installers (OneDrive, Teams, audio drivers,
  VPN clients) writing to `HKLM\...\Run` with their own signed binary. The
  `by_process` and `by_value` aggregations help to separate the common from the rare
  (frequency analysis / stacking).
- **Next steps**: compute the hash of the binary in `details` and look it up in MISP
  (H15); check who created the file and when (Sysmon EID 11) and the process tree
  of the writer (EID 1).
- **If nothing shows up**: run EMU-04 (it writes to HKCU, so it needs Sysmon).

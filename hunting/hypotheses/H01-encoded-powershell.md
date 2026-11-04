---
id: H01
title: Encoded or obfuscated PowerShell
techniques: [T1059.001, T1027]
tactics: [execution, stealth]
platforms: [windows]
data_sources:
  - Sysmon EID 1 (process creation)
  - PowerShell Operational EID 4104 (Script Block Logging)
index: wazuh-archives-*
emulation: [EMU-01]
---

# H01 · Encoded or obfuscated PowerShell

## Hypothesis

An attacker with execution on a Windows host uses PowerShell with the command
Base64-encoded (`-EncodedCommand`) or obfuscated (`IEX`, `FromBase64String`,
in-memory downloads) so that the real command does not appear in clear text in the logs.

## Question

Which `powershell.exe`/`pwsh.exe` processes have been launched in the last 7 days with
`-e`/`-enc`/`-EncodedCommand`, a hidden window, `IEX`, `FromBase64String` or
`DownloadString`, and which script blocks (4104) contain those same strings?
Who launched them and from which parent process?

## Data required

- **Sysmon EID 1** in `Microsoft-Windows-Sysmon/Operational`: `data.win.eventdata.image`,
  `commandLine`, `parentImage`, `user`.
- **EID 4104** in `Microsoft-Windows-PowerShell/Operational` with Script Block Logging
  enabled by GPO: `data.win.eventdata.scriptBlockText`. The channel has to be added to the
  agent `ossec.conf` (`<localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format></localfile>`).
- `wazuh-archives-*` index (requires `logall_json` on the manager), because most
  PowerShell executions do not raise an alert and never reach `wazuh-alerts-*`.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:1 and data.win.eventdata.image:(*powershell.exe or *pwsh.exe) and data.win.eventdata.commandLine:(*-enc* or *-EncodedCommand* or *FromBase64String* or *IEX* or *DownloadString* or *hidden*)
```

### OpenSearch Query DSL

```json
{
  "size": 100,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.eventdata.user", "data.win.eventdata.parentImage", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.scriptBlockText"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}],
      "should": [
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
          {"term": {"data.win.system.eventID": "1"}},
          {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\powershell.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\pwsh.exe", "case_insensitive": true}}}
          ], "minimum_should_match": 1}},
          {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "* -e *", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "* -en*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "* -ec *", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*frombase64string*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*invoke-expression*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*iex*(*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*downloadstring*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*-w* hid*", "case_insensitive": true}}}
          ], "minimum_should_match": 1}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.eventID": "4104"}},
          {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.scriptBlockText": {"value": "*frombase64string*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.scriptBlockText": {"value": "*downloadstring*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.scriptBlockText": {"value": "*invoke-expression*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.scriptBlockText": {"value": "*[char]*-join*", "case_insensitive": true}}}
          ], "minimum_should_match": 1}}
        ]}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

## Interpretation

- **What is suspicious**: `-e`/`-enc` with a long Base64 launched by `winword.exe`,
  `excel.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe` or a service; the combination
  `-nop -w hidden -enc`; a 4104 that decodes Base64 and passes it to `IEX`. Decode
  the Base64 (UTF-16LE) to see the real command.
- **Common false positives**: SCCM/Intune, inventory scripts and monitoring
  agents that use `-EncodedCommand` to avoid quoting problems.
  Group by `parentImage` + `user` and document the legitimate ones.
- **Next steps**: pivot on `agent.name` and the exact time to network connections
  (Sysmon EID 3, H11), files created (EID 11) and persistence (H03, H04).
- **If nothing shows up**: run EMU-01; if it does not show up either, Sysmon EID 1, the
  4104 channel or the archives index is missing.
- **Note**: the patterns of the JSON query are case-insensitive; the DQL ones are not.

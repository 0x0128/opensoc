---
id: H07
title: Clearing of Windows event logs
techniques: [T1685.005]
legacy_techniques: [T1070.001]
tactics: [defense-impairment]
platforms: [windows]
data_sources:
  - Security EID 1102 (audit log cleared)
  - System EID 104 (event log cleared)
  - Sysmon EID 1 (wevtutil / Clear-EventLog)
index: wazuh-archives-*
emulation: [EMU-05]
---

# H07 · Event log clearing

> ATT&CK moved *Clear Windows Event Logs* from T1070.001 to **T1685.005**. The Wazuh
> ruleset and many custom rules still use the old ID: search for both.

## Hypothesis

After acting on a host, the attacker clears the event logs (`wevtutil cl`,
`Clear-EventLog`, `Remove-EventLog`, API) to remove their local traces.

## Question

Which hosts have logged a clearing of the Security log (1102) or of any other
log (104), who did it and with which command, in the last 30 days?

## Data required

- **Security 1102** and **System 104** (collected by the Wazuh agent by default):
  `agent.name`, `data.win.system.channel`, `data.win.system.computer`. The user
  appears in the UserData block of the event (check it in `full_log` if your decoder does not
  extract it to `data.win.eventdata.subjectUserName`).
- **Sysmon EID 1**: `commandLine` with `wevtutil cl`, `Clear-EventLog`,
  `Remove-EventLog`.
- `wazuh-archives-*` index. The clearing only affects the host: what the agent sent
  before is still in the indexer, and that is what makes hunting possible.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
(data.win.system.eventID:1102 and data.win.system.channel:Security) or (data.win.system.eventID:104 and data.win.system.channel:System) or data.win.eventdata.commandLine:(*wevtutil*cl* or *Clear-EventLog* or *Remove-EventLog*)
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.system.channel", "data.win.eventdata.subjectUserName", "data.win.eventdata.user", "data.win.eventdata.parentImage", "data.win.eventdata.commandLine", "full_log"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}],
      "should": [
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Security"}},
          {"term": {"data.win.system.eventID": "1102"}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "System"}},
          {"term": {"data.win.system.eventID": "104"}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
          {"term": {"data.win.system.eventID": "1"}},
          {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*wevtutil* cl *", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*wevtutil*clear-log*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*clear-eventlog*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*remove-eventlog*", "case_insensitive": true}}}
          ], "minimum_should_match": 1}}
        ]}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {"by_host": {"terms": {"field": "agent.name", "size": 50}}}
}
```

## Interpretation

- **What is suspicious**: practically any 1102 outside a documented
  procedure; several logs cleared within seconds (`for /F ... wevtutil cl`); clearings
  on several hosts in a row (activity after lateral movement or before ransomware);
  clearings done by service accounts or from a `cmd.exe` launched by an odd process.
- **Common false positives**: system images that clear logs during
  deployment (sysprep) and maintenance scripts. They must be documented.
- **Next steps**: review in the indexer what the host sent in the 24 h
  before the clearing (everything the attacker wanted to hide is already here): logons
  (H09), services (H05), tasks (H04), PowerShell (H01).
- **If nothing shows up**: run EMU-05 (it clears the System log of the lab host:
  it requires `--allow-irreversible`).
- **Linux**: the equivalent (T1685.006) is seen with FIM/auditd on `/var/log`
  (`syscheck.event:deleted` or truncations); it is not covered by this query.

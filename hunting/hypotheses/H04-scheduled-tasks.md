---
id: H04
title: Scheduled tasks created for persistence or execution
techniques: [T1053.005]
tactics: [execution, persistence, privilege-escalation]
platforms: [windows]
data_sources:
  - Security EID 4698 (scheduled task created)
  - Sysmon EID 1 (schtasks.exe / Register-ScheduledTask)
  - TaskScheduler Operational EID 106 (optional)
index: wazuh-archives-*
emulation: [EMU-03]
---

# H04 · Suspicious scheduled tasks

## Hypothesis

An attacker creates scheduled tasks (`schtasks /create`, `Register-ScheduledTask`,
COM) that run at logon, at startup or as SYSTEM to keep
access or to run payloads remotely.

## Question

Which tasks have been created in the last 14 days, by which user, with which action
(`/tr`, `<Command>`) and trigger (`ONLOGON`, `ONSTART`, `/ru SYSTEM`)? Was any of them
created remotely (`/s <host>`)?

## Data required

- **Security 4698** (needs the advanced audit policy *Object Access →
  Other Object Access Events*): `data.win.eventdata.taskName`, `taskContent` (XML of
  the task), `subjectUserName`.
- **Sysmon EID 1**: `image` = `schtasks.exe` with `commandLine` `/create`, or PowerShell
  with `Register-ScheduledTask`/`New-ScheduledTask`.
- Optional: the `Microsoft-Windows-TaskScheduler/Operational` channel (EID 106) added to
  the agent `ossec.conf`.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:4698 or (data.win.system.eventID:1 and data.win.eventdata.image:*\\schtasks.exe and data.win.eventdata.commandLine:*create*) or data.win.eventdata.commandLine:*Register-ScheduledTask*
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.system.channel", "data.win.eventdata.taskName", "data.win.eventdata.taskContent", "data.win.eventdata.subjectUserName", "data.win.eventdata.user", "data.win.eventdata.parentImage", "data.win.eventdata.commandLine"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-14d"}}}],
      "should": [
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Security"}},
          {"term": {"data.win.system.eventID": "4698"}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Microsoft-Windows-TaskScheduler/Operational"}},
          {"term": {"data.win.system.eventID": "106"}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
          {"term": {"data.win.system.eventID": "1"}},
          {"bool": {"should": [
            {"bool": {"filter": [
              {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\schtasks.exe", "case_insensitive": true}}},
              {"wildcard": {"data.win.eventdata.commandLine": {"value": "*create*", "case_insensitive": true}}}
            ]}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*register-scheduledtask*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*new-scheduledtask*", "case_insensitive": true}}}
          ], "minimum_should_match": 1}}
        ]}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_task": {"terms": {"field": "data.win.eventdata.taskName", "size": 30}},
    "by_creator": {"terms": {"field": "data.win.eventdata.subjectUserName", "size": 20}}
  }
}
```

## Interpretation

- **What is suspicious**: actions that run `cmd.exe /c`, `powershell -enc`,
  `mshta`, `rundll32` or binaries in `%TEMP%`, `%APPDATA%`, `C:\Users\Public`;
  `ONLOGON`/`ONSTART` triggers with `/ru SYSTEM`; tasks created by non-administrator
  users or from `wmiprvse.exe`/`services.exe` (remote creation); names
  that imitate Microsoft tasks but live outside `\Microsoft\Windows\`; `/s <host>`
  (creation on another host = lateral movement, see H09).
- **Common false positives**: updaters (Google, Adobe, Office), management
  agents and GPOs. The `by_task` and `by_creator` aggregations make it possible to discard the
  tasks that appear across the whole fleet.
- **Next steps**: read `taskContent` (XML) to see `<Exec><Command>`; look for the
  first execution of the command (Sysmon EID 1 with `parentImage` `svchost.exe -k
  netsvcs -p -s Schedule` or `taskeng.exe`) and the hash of the binary in MISP (H15).
- **If nothing shows up**: run EMU-03 and check that at least the EID 1 of
  `schtasks.exe` arrives; if the 4698 is missing, review the audit policy.

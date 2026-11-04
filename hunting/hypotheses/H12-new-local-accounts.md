---
id: H12
title: New local accounts or accounts added to privileged groups
techniques: [T1136.001, T1098]
tactics: [persistence, privilege-escalation]
platforms: [windows, linux]
data_sources:
  - Security EID 4720 (account created), 4732/4728/4756 (member added to a group)
  - auth.log / secure / journald (useradd, usermod, groupadd, gpasswd)
index: wazuh-archives-*
emulation: [EMU-07]
---

# H12 · New or privileged local accounts

## Hypothesis

To avoid depending on a single credential, the attacker creates a local (or
domain) account and adds it to Administrators / sudo / wheel, often with a name that
imitates a service account.

## Question

In the last 30 days, which accounts have been created and which users have been added to
groups (especially privileged ones), on which hosts, who did it and with which command?

## Data required

- **Windows Security**: 4720 (`data.win.eventdata.targetUserName` = new account,
  `subjectUserName` = who creates it), 4732 local, 4728 global, 4756 universal
  (`targetUserName` = group, `memberSid`/`memberName` = member added).
- **Linux**: `useradd`, `adduser`, `usermod`, `groupadd`, `gpasswd` lines in
  auth.log/secure/journald. Wazuh stores the program in `predecoder.program_name`
  and the text in `full_log`.
- `wazuh-archives-*` index (the default rules also alert on these events,
  so `wazuh-alerts-*` works for most of them).

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:(4720 or 4732 or 4728 or 4756) or predecoder.program_name:(useradd or adduser or usermod or groupadd or gpasswd)
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName", "data.win.eventdata.memberSid", "data.win.eventdata.memberName", "predecoder.program_name", "full_log"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}],
      "should": [
        {"bool": {"filter": [
          {"term": {"data.win.system.channel": "Security"}},
          {"terms": {"data.win.system.eventID": ["4720", "4732", "4728", "4756"]}}
        ]}},
        {"terms": {"predecoder.program_name": ["useradd", "adduser", "usermod", "groupadd", "gpasswd"]}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_host": {"terms": {"field": "agent.name", "size": 50}},
    "windows_groups": {"terms": {"field": "data.win.eventdata.targetUserName", "size": 30}}
  }
}
```

## Interpretation

- **What is suspicious**: a 4720 followed within seconds by a 4732 to `Administrators`/
  `Administradores` or `Remote Desktop Users`; accounts created outside business hours or
  by accounts that do not belong to the systems team; names like `support`, `admin1`,
  `svc_backup`, a trailing `$` on user accounts; on Linux `useradd -o -u 0`
  (duplicated UID 0), `usermod -aG sudo|wheel`, accounts with a `/bin/bash` shell
  created with `-r` (system accounts), and accounts created by a web process (`www-data`).
- **Common false positives**: user onboarding by the systems team,
  image deployments, packages that create their service user when installed
  (with a `nologin` shell). Cross-check with the change tickets.
- **Next steps**: look for the logons of the new account (4624 / sshd
  `Accepted`), its processes and whether SSH keys were added to it (H13). Disable it if
  it is not justified.
- **If nothing shows up**: run EMU-07 (it creates `evil_user` on Linux and deletes it at
  the end).

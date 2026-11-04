---
id: H09
title: Lateral movement over RDP or SMB with accounts that touch many hosts
techniques: [T1021.001, T1021.002]
tactics: [lateral-movement]
platforms: [windows]
data_sources:
  - Security EID 4624 (successful logon, types 3 and 10)
  - Security EID 4648 (logon with explicit credentials)
index: wazuh-archives-*
emulation: []
---

# H09 · Lateral movement over RDP/SMB

## Hypothesis

With stolen credentials (H02, H08), the attacker moves between hosts over RDP
(logonType 10) or SMB/WinRM/PsExec (logonType 3). A user account that suddenly
logs on to many hosts, or from a new source, is the signal.

## Question

In the last 7 days, which (non-machine) accounts have made network or
RDP logons on the most distinct hosts, from how many sources, and which of them do so on hosts
they had never logged on to before?

## Data required

- **Security 4624**: `data.win.eventdata.targetUserName`, `targetDomainName`,
  `logonType`, `ipAddress`, `workstationName`, `authenticationPackageName`
  (NTLM/Kerberos), `agent.name` (destination host).
- **Security 4648** to see the source host when explicit credentials are used
  (`runas`, PsExec with `-u`).
- `wazuh-archives-*` index (if your ruleset alerts on 4624, `wazuh-alerts-*`
  works as well).

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:4624 and data.win.eventdata.logonType:(3 or 10) and not data.win.eventdata.targetUserName:*$ and not data.win.eventdata.ipAddress:("-" or "127.0.0.1" or "::1")
```

### OpenSearch Query DSL

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-7d"}}},
        {"term": {"data.win.system.channel": "Security"}},
        {"term": {"data.win.system.eventID": "4624"}},
        {"terms": {"data.win.eventdata.logonType": ["3", "10"]}}
      ],
      "must_not": [
        {"wildcard": {"data.win.eventdata.targetUserName": {"value": "*$"}}},
        {"terms": {"data.win.eventdata.targetUserName": ["ANONYMOUS LOGON", "DWM-1", "UMFD-0", "UMFD-1"]}},
        {"terms": {"data.win.eventdata.ipAddress": ["-", "127.0.0.1", "::1"]}}
      ]
    }
  },
  "aggs": {
    "by_account": {
      "terms": {"field": "data.win.eventdata.targetUserName", "size": 30, "order": {"hosts": "desc"}},
      "aggs": {
        "hosts": {"cardinality": {"field": "agent.name"}},
        "sources": {"cardinality": {"field": "data.win.eventdata.ipAddress"}},
        "logon_type": {"terms": {"field": "data.win.eventdata.logonType", "size": 2}},
        "package": {"terms": {"field": "data.win.eventdata.authenticationPackageName", "size": 3}},
        "host_list": {"terms": {"field": "agent.name", "size": 10}}
      }
    }
  }
}
```

## Interpretation

- **How to read it**: accounts are sorted by number of distinct hosts.
  - A normal user account with a high `hosts`, especially with `logon_type` 10
    (RDP) or with `package` NTLM in a domain that uses Kerberos → possible lateral
    movement or Pass-the-Hash.
  - `sources` = 1 and a high `hosts` → a single compromised host acting as a
    pivot: investigate that source.
  - Compare with a previous week (`--from now-14d --to now-7d`): what matters is
    what is **new** for that account.
- **Common false positives**: administration and service accounts (backup,
  inventory, SCCM, scanners) that by design touch many hosts. Document them and
  add them to the `must_not`.
- **Next steps**: for the suspicious account, build the 4624/4648 timeline
  per host, and on each destination look for what came next: services (H05), tasks
  (H04), PowerShell (H01), LSASS access (H02).
- **Validation**: there is no automatic scenario; generate RDP/SMB logons between lab
  hosts with a test account.

---
id: H08
title: Brute force and password spraying against Windows and SSH
techniques: [T1110.001, T1110.003]
tactics: [credential-access]
platforms: [windows, linux]
data_sources:
  - Security EID 4625 (failed logon)
  - sshd in auth.log / secure / journald
  - Wazuh alerts of the authentication_failed group
index: wazuh-alerts-*
emulation: []
---

# H08 · Brute force and password spraying

## Hypothesis

An attacker tries passwords against RDP/SMB/SSH: many passwords for one
account (brute force, T1110.001) or one password for many accounts (spraying,
T1110.003), from one or a few IPs.

## Question

In the last 24 hours, which source IPs accumulate the most failed logons,
against how many distinct accounts and how many hosts? Is there any success from those IPs
after the failures?

## Data required

- Wazuh alerts with `rule.groups` `authentication_failed`, `invalid_login` or
  `authentication_failures` (the default Windows and sshd rules already carry them).
- Windows (4625): `data.win.eventdata.ipAddress`, `targetUserName`, `logonType`,
  `status`/`subStatus` (`0xC000006A` wrong password, `0xC0000064` non-existent
  user).
- Linux (sshd): `data.srcip`, `data.dstuser` (depending on the decoder, the user may
  come in `data.srcuser`).
- `wazuh-alerts-*` index: alerts are used here, not raw events.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
rule.groups:(authentication_failed or invalid_login or authentication_failures)
```

### OpenSearch Query DSL

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-24h"}}},
        {"terms": {"rule.groups": ["authentication_failed", "invalid_login", "authentication_failures"]}}
      ]
    }
  },
  "aggs": {
    "windows_sources": {
      "terms": {"field": "data.win.eventdata.ipAddress", "size": 20, "min_doc_count": 10},
      "aggs": {
        "distinct_accounts": {"cardinality": {"field": "data.win.eventdata.targetUserName"}},
        "hosts": {"cardinality": {"field": "agent.name"}},
        "logon_type": {"terms": {"field": "data.win.eventdata.logonType", "size": 3}},
        "substatus": {"terms": {"field": "data.win.eventdata.subStatus", "size": 3}}
      }
    },
    "linux_sources": {
      "terms": {"field": "data.srcip", "size": 20, "min_doc_count": 10},
      "aggs": {
        "distinct_accounts": {"cardinality": {"field": "data.dstuser"}},
        "hosts": {"cardinality": {"field": "agent.name"}}
      }
    }
  }
}
```

## Interpretation

- **How to read it**: for each IP, `doc_count` is the number of failures.
  - Many failures and a **high `distinct_accounts`** (dozens) with few attempts per
    account → **spraying**.
  - Many failures and **`distinct_accounts` = 1-2** → **brute force** against that account.
  - `hosts` > 1 from the same IP → the attacker is walking the network.
  - Dominant `substatus` `0xC0000064` → they are trying user names (enumeration).
- **What matters is the success**: for each suspicious IP search for
  `rule.groups:authentication_success and (data.srcip:<IP> or data.win.eventdata.ipAddress:<IP>)`
  after the first failure. A success after the burst = compromised credential:
  block, reset the password and continue with H09.
- **Common false positives**: services with an expired password in a loop (one
  account, one internal IP, steady rate), authorized vulnerability scanners,
  load balancers/proxies that concentrate traffic on one IP. An `ipAddress` of `-` or `::1`
  is usually a local failure, not a remote one.
- **Tuning**: `min_doc_count` (10) defines what "a lot" is; raise it if the lab
  is exposed to the Internet.
- **Validation**: there is no emulation scenario; in the lab you can generate
  failures with `hydra`/`crackmapexec` against your own host or with the Atomic Red Team
  T1110.001/T1110.003 tests.

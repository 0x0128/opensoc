---
id: H14
title: Execution of binaries and scripts from /tmp, /dev/shm or /var/tmp
techniques: [T1059.004]
tactics: [execution]
platforms: [linux]
data_sources:
  - auditd (execve) collected by Wazuh
index: wazuh-archives-*
emulation: []
---

# H14 · Execution from temporary directories on Linux

## Hypothesis

After exploiting a service or getting in over SSH, the attacker downloads their tool into
a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`) and
runs it from there, because no privileges are needed to write to those paths.

## Question

In the last 7 days, which executables or scripts have been launched from temporary
directories, by which user (`auid` = user who logged in) and with which arguments?

## Data required

- **auditd** with a keyed execve rule, for example
  `-a always,exit -F arch=b64 -S execve -k audit-wazuh-c` (and the `b32` equivalent),
  and the agent reading `/var/log/audit/audit.log` (`log_format` `audit`).
- Wazuh fields: `data.audit.exe`, `data.audit.command`, `data.audit.execve.a0`,
  `a1`, `a2`..., `data.audit.cwd`, `data.audit.uid`, `data.audit.auid`,
  `data.audit.key`.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.audit.exe:(/tmp/* or /var/tmp/* or /dev/shm/* or /run/user/*) or data.audit.execve.a1:(/tmp/* or /var/tmp/* or /dev/shm/*)
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.audit.exe", "data.audit.command", "data.audit.execve", "data.audit.cwd", "data.audit.uid", "data.audit.auid", "data.audit.key"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}],
      "should": [
        {"prefix": {"data.audit.exe": "/tmp/"}},
        {"prefix": {"data.audit.exe": "/var/tmp/"}},
        {"prefix": {"data.audit.exe": "/dev/shm/"}},
        {"prefix": {"data.audit.exe": "/run/user/"}},
        {"prefix": {"data.audit.execve.a1": "/tmp/"}},
        {"prefix": {"data.audit.execve.a1": "/var/tmp/"}},
        {"prefix": {"data.audit.execve.a1": "/dev/shm/"}},
        {"prefix": {"data.audit.execve.a2": "/tmp/"}},
        {"prefix": {"data.audit.execve.a2": "/dev/shm/"}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_executable": {
      "terms": {"field": "data.audit.exe", "size": 30},
      "aggs": {
        "servers": {"cardinality": {"field": "agent.name"}},
        "users": {"terms": {"field": "data.audit.auid", "size": 5}}
      }
    }
  }
}
```

## Interpretation

- **What is suspicious**: executables with random names or that imitate system
  processes (`/tmp/.X11-unix/kworker`, `/dev/shm/sshd`), hidden directories
  (`/tmp/.ICE-unix/.x/`), interpreters (`bash`, `sh`, `python`, `perl`) whose `a1` is a
  script in `/tmp`, executions with the `uid` of a web service (`www-data`, `nginx`,
  `tomcat`) → likely exploitation of the application. An `auid` different from the `uid`
  indicates escalation (`sudo`, `su`).
- **Common false positives**: installers and configuration scripts that
  unpack into `/tmp` (`.run` packages, `pip`/`npm` compiling), CI
  tools. The `by_executable` / `servers` aggregations help to see what repeats
  across the whole fleet.
- **Next steps**: retrieve the file (if it is still there) and its hash; find out how it arrived
  (earlier `curl`/`wget` by the same `auid`, H06 on Linux), outbound connections and
  persistence (H13). Upload the IOCs to MISP with `opensoc-ioc import`.
- **Validation**: it is not in the scenario catalog; you can run
  `Invoke-AtomicTest T1059.004 -TestGuids 8cd1947b-4a54-41fb-b5ea-07d0ace04f81`
  (*New script file in the tmp directory*) by hand on a lab server.

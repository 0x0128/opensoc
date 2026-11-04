---
id: H13
title: Linux persistence seen by FIM (cron, systemd, SSH keys, preload)
techniques: [T1053.003, T1543.002, T1098.004, T1574.006]
tactics: [persistence, privilege-escalation]
platforms: [linux]
data_sources:
  - Wazuh FIM (syscheck), ideally with realtime or whodata
index: wazuh-alerts-*
emulation: [EMU-08, EMU-09, EMU-10]
---

# H13 · Linux persistence seen by FIM

## Hypothesis

An attacker with access to a Linux server sets up persistence by modifying files
that the system runs or trusts: cron (`/etc/cron*`, `/var/spool/cron`), systemd
units, `authorized_keys`, `/etc/ld.so.preload`, profile scripts or `sudoers`.

## Question

In the last 14 days, which persistence files have been created or modified,
on which servers, by which user and process (whodata), and with which new content
(`report_changes`)?

## Data required

- **Wazuh FIM** with these paths in the agent `<syscheck>`, preferably with
  `realtime="yes"` or `whodata="yes"` (otherwise they are only seen in the periodic scan,
  every 12 h by default) and `report_changes="yes"` to see the diff:
  `/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/etc/crontab,/var/spool/cron,`
  `/etc/systemd/system,/usr/lib/systemd/system,/etc/ld.so.preload,/etc/profile.d,`
  `/etc/sudoers,/etc/sudoers.d,/root/.ssh` and `/home` with `restrict` to
  `authorized_keys`.
- Fields: `syscheck.path`, `syscheck.event` (`added`/`modified`/`deleted`),
  `syscheck.diff`, `syscheck.uname_after`, `syscheck.sha256_after`,
  `syscheck.audit.user.name`, `syscheck.audit.process.name` (whodata only).
- `wazuh-alerts-*` index: every FIM change raises an alert (`rule.groups:
  syscheck`).

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
rule.groups:syscheck and syscheck.event:(added or modified) and (syscheck.path:/etc/cron* or syscheck.path:/var/spool/cron* or syscheck.path:/etc/systemd/system* or syscheck.path:/usr/lib/systemd/system* or syscheck.path:*authorized_keys* or syscheck.path:/etc/ld.so.preload or syscheck.path:/etc/profile.d* or syscheck.path:/etc/sudoers*)
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "rule.id", "rule.description", "syscheck.path", "syscheck.event", "syscheck.diff", "syscheck.uname_after", "syscheck.sha256_after", "syscheck.audit.user.name", "syscheck.audit.process.name"],
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-14d"}}},
        {"term": {"rule.groups": "syscheck"}},
        {"terms": {"syscheck.event": ["added", "modified"]}}
      ],
      "should": [
        {"prefix": {"syscheck.path": "/etc/cron"}},
        {"prefix": {"syscheck.path": "/var/spool/cron"}},
        {"prefix": {"syscheck.path": "/etc/systemd/system"}},
        {"prefix": {"syscheck.path": "/usr/lib/systemd/system"}},
        {"prefix": {"syscheck.path": "/lib/systemd/system"}},
        {"prefix": {"syscheck.path": "/etc/init.d"}},
        {"term": {"syscheck.path": "/etc/rc.local"}},
        {"term": {"syscheck.path": "/etc/ld.so.preload"}},
        {"prefix": {"syscheck.path": "/etc/profile.d"}},
        {"prefix": {"syscheck.path": "/etc/sudoers"}},
        {"wildcard": {"syscheck.path": {"value": "*/.ssh/authorized_keys*"}}},
        {"wildcard": {"syscheck.path": {"value": "*/.bashrc"}}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_path": {
      "terms": {"field": "syscheck.path", "size": 50},
      "aggs": {"servers": {"cardinality": {"field": "agent.name"}}}
    }
  }
}
```

## Interpretation

- **What is suspicious**:
  - **cron**: entries that run from `/tmp`, `/dev/shm`, `curl|wget ... | sh`,
    `bash -i >& /dev/tcp/...`, Base64; new files in `/etc/cron.d` with generic
    names.
  - **systemd**: new units with an `ExecStart` outside `/usr`, `Restart=always` on
    binaries in `/tmp`/`/var/tmp`, units created outside a package installation.
  - **authorized_keys**: keys added to `root` or to service accounts; changes
    made by a process other than `sshd`/`ssh-copy-id`/a configuration manager.
  - **`/etc/ld.so.preload`**: almost always malicious (userland rootkits).
  - `servers` = 1 in `by_path` → a one-off change, not a general deployment.
- **Common false positives**: package updates (`dpkg`/`rpm`/`yum`
  as `syscheck.audit.process.name`), Ansible/Puppet/Chef, `logrotate` and `certbot`
  in cron. With whodata they are quickly separated by process.
- **Next steps**: read `syscheck.diff`, identify the user and the process
  (whodata/auditd), review the SSH logons at that time and the execution of the
  payload (H14). Check with `sha256_after` whether the file is already in MISP.
- **If nothing shows up**: run EMU-08, EMU-09 and EMU-10. If the scenarios report MISSED,
  it almost always means that FIM is not real-time on those paths.

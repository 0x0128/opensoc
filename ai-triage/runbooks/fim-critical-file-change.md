---
id: fim-critical-file-change
title: Unauthorized change to critical system files (FIM)
mitre: [T1565.001, T1543.002, T1546.004, T1098.004]
tactics: [Impact, Persistence]
wazuh_groups: [syscheck, syscheck_entry_modified, syscheck_entry_added, syscheck_file, ossec]
wazuh_rules: ["550", "553", "554", "594", "597"]
keywords: [file integrity, fim, syscheck, checksum changed, etc passwd, shadow, sudoers, authorized_keys, systemd, crontab, binary modified]
severity_hint: medium
---
# Unauthorized change to critical system files (FIM)

The Wazuh file integrity monitoring module (syscheck) detects the creation, modification or
deletion of sensitive files: system binaries, authentication configuration, systemd units,
crontab or authorized SSH keys.

## Indicators
- Rule 550 (checksum changed), 554 (file added), 553 (file deleted) on critical paths.
- Changes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `~/.ssh/authorized_keys`, `/etc/systemd/system/`, `/etc/cron*`.
- System binaries (`/bin`, `/usr/bin`, `/sbin`) whose hash differs from the package one.

## Triage
1. Review the diff or the changed attributes (hash, owner, permissions) reported by syscheck.
2. Identify the user and process that made the change (whodata / auditd if enabled).
3. Correlate with maintenance windows, deployments or package updates.
4. For binaries, verify the hash against the original package (`rpm -V`, `debsums`).

## Containment
1. If the change is not authorized, preserve a copy of the modified file as evidence.
2. Restore the file from configuration management or a known-good backup.
3. If it affects authentication or persistence, review active sessions and isolate the host if it is compromised.

## Eradication and recovery
1. Remove SSH keys, systemd units or cron entries added by the attacker.
2. Enable whodata on the critical paths to improve future attribution.

## Escalation
- Escalate if system binaries or authentication files are modified, or if there is no operational explanation.

## False positives
- Package updates, configuration management (Ansible, Puppet) and administrator changes with a ticket.

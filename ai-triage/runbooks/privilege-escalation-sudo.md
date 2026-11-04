---
id: privilege-escalation-sudo
title: Privilege escalation through sudo, su or SUID binaries
mitre: [T1548.003, T1548.001, T1068]
tactics: [Privilege Escalation, Defense Evasion]
wazuh_groups: [sudo, su, pam, audit, audit_command, syslog]
wazuh_rules: ["5401", "5402", "5403", "5404", "5405", "5303", "80792"]
keywords: [sudo, su, privilege escalation, root shell, suid, setuid, incorrect password attempts, not in sudoers, pkexec, exploit]
severity_hint: high
---
# Privilege escalation through sudo, su or SUID binaries

Anomalous use of `sudo` or `su`, attempts by users who are not in sudoers, unusual sudo commands
(shells, editors with a shell escape) or exploitation of SUID binaries and local vulnerabilities.

## Indicators
- Rule 5401 (three failed sudo attempts), 5402 (sudo to root), 5405 (user not in sudoers).
- `sudo` running `bash`, `sh`, `vi`, `find -exec`, `python -c` or other binaries with a known escape (GTFOBins).
- New files with the SUID bit, or use of `pkexec` and kernel exploits.

## Triage
1. Identify the user, the exact command run with privileges and the originating terminal or session.
2. Check whether the user has a legitimate administrative role and whether the command is usual for them.
3. Review the user's activity before and after (downloads, compilations, file changes).

## Containment
1. If it is not justified, lock the account and close its active sessions.
2. Revoke or restrict the sudoers rules that allow escaping to a shell.
3. Isolate the host if an unauthorized root shell was obtained.

## Eradication and recovery
1. Apply operating system patches if a local vulnerability was exploited.
2. Remove unnecessary SUID bits and review persistence created with root privileges.

## Escalation
- Escalate to tier 2 if unauthorized root access was obtained or if vulnerabilities were exploited.

## False positives
- Administrators running maintenance tasks with their own account (validate with the team).

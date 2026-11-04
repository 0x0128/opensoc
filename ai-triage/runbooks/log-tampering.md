---
id: log-tampering
title: Deletion or tampering of audit logs
mitre: [T1070, T1070.001, T1070.002, T1562.001, T1562.002]
tactics: [Defense Evasion]
wazuh_groups: [windows, windows_security, log_cleared, audit, ossec, agent_stopped]
wazuh_rules: ["63103", "63104", "506", "504", "80705"]
keywords: [event log cleared, audit log cleared, 1102, 104, wevtutil, history cleared, auditd stopped, agent stopped, log deletion, tampering]
severity_hint: high
---
# Deletion or tampering of audit logs

Windows event logs are cleared, logs are truncated on Linux, or auditd or the Wazuh agent is
stopped. Attackers do this to hide their activity, usually right after carrying it out.

## Indicators
- Windows events 1102 (security log cleared) and 104 (system log cleared).
- Use of `wevtutil cl`, `Clear-EventLog`, deletion of `~/.bash_history` or truncation of `/var/log/*`.
- Rule 506 / 504: Wazuh agent stopped or disconnected without planned maintenance.

## Triage
1. Identify the account and process that cleared the logs and the exact time.
2. Review the events that did reach the Wazuh manager before the deletion (central copy).
3. Look for earlier suspicious activity from the same user or host: logons, execution, lateral movement.

## Containment
1. Treat the host as potentially compromised: isolate it if there are other indicators.
2. Disable the account involved unless it is an administrator carrying out an approved change.
3. Restore the audit service and the Wazuh agent and verify that they report again.

## Eradication and recovery
1. Restrict who can clear logs (audit policy and permissions).
2. Forward logs in real time to immutable central storage.

## Escalation
- Always escalate to tier 2: log deletion is almost never benign outside a maintenance window.

## False positives
- Planned log rotation or maintenance documented in a change ticket.

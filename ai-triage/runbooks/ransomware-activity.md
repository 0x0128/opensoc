---
id: ransomware-activity
title: Ransomware-like activity
mitre: [T1486, T1490, T1489]
tactics: [Impact]
wazuh_groups: [syscheck, ossec, ransomware, vss, sysmon_event_11]
wazuh_rules: ["550", "553", "554", "100100"]
keywords: [ransomware, encryption, encrypted files, mass file modification, vssadmin, shadow copies, ransom note, file extension]
severity_hint: critical
---
# Ransomware-like activity

Mass modification or renaming of files, deletion of volume shadow copies or ransom notes
appearing. It is a top-priority incident: response time limits the damage.

## Indicators
- Burst of integrity alerts (FIM, rules 550/553/554) on many files within a short time.
- New unknown extensions or `README`, `HOW_TO_DECRYPT` files in multiple folders.
- Execution of `vssadmin delete shadows`, `wbadmin delete catalog` or `bcdedit /set recoveryenabled no`.

## Triage
1. Confirm the pattern: number of files modified per minute and resulting extensions.
2. Identify the process and the user making the modifications (Sysmon 11 / auditd).
3. Determine the scope: other agents with the same pattern and affected network shares.

## Containment
1. Immediately isolate the affected hosts from the network (do not power them off, to preserve memory).
2. Disable the user account involved and revoke its sessions and tokens.
3. Disconnect the affected network shares or make them read-only.
4. Protect the backups: verify that they are isolated and have not been altered.

## Eradication and recovery
1. Identify the entry vector (exposed RDP, phishing, vulnerability) and close it.
2. Restore from verified backups after removing the attacker's persistence.
3. Reset privileged domain credentials if administrative accounts were compromised.

## Escalation
- Activate the incident response plan and notify management, legal and data protection.

## False positives
- Legitimate mass encryption, compression or backup processes (validate the signed process and the maintenance window).

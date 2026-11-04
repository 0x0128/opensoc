---
id: ssh-brute-force
title: SSH brute force and password spraying
mitre: [T1110, T1110.001, T1110.003, T1021.004]
tactics: [Credential Access, Lateral Movement]
wazuh_groups: [sshd, authentication_failures, authentication_failed, invalid_login]
wazuh_rules: ["5710", "5711", "5712", "5716", "5720", "5758", "5763", "40111"]
keywords: [ssh, sshd, brute force, password spraying, failed password, invalid user, authentication failure, login]
severity_hint: medium
---
# SSH brute force and password spraying

Multiple failed SSH authentication attempts from one or several sources against one or several
users. The real risk depends on whether any attempt succeeded and on whether the service is
exposed to the Internet.

## Indicators
- Wazuh rules 5710/5712 (non-existent user or repeated failures), 5720/5763 (multiple failures).
- Many different users from the same IP (password spraying) or many attempts against a single user.
- A later `Accepted password` or `Accepted publickey` from the same source IP is critical.

## Triage
1. Check whether there is a successful logon (rule 5715) from the source IP after the failures.
2. Determine whether the source IP is internal or external and check its reputation in the threat intel platform.
3. Check whether the targeted users exist and whether they are privileged (root, sudoers, service accounts).
4. Measure volume and time window: hundreds of attempts within minutes point to an automated tool.

## Containment
1. Block the source IP on the perimeter firewall or through Wazuh active response (`firewall-drop`).
2. If there was a successful logon, isolate the host and force-close the user's active SSH sessions.
3. Reset the password or revoke the keys of the compromised users.

## Eradication and recovery
1. Disable password authentication (`PasswordAuthentication no`) and require keys or MFA.
2. Restrict SSH access by source (bastion, VPN) and set a low `MaxAuthTries`.
3. Review `authorized_keys`, cron and new users created after a successful logon.

## Escalation
- Escalate to tier 2 immediately if there is a successful logon after the failures or if the target is a critical server.

## False positives
- Automation or monitoring scripts with expired credentials.
- Legitimate users who forget their password (few attempts, known internal IP).

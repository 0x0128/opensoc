---
id: account-manipulation
title: Suspicious creation or modification of privileged accounts
mitre: [T1136, T1136.001, T1136.002, T1098]
tactics: [Persistence, Privilege Escalation]
wazuh_groups: [adduser, account_changed, group_changed, windows_security, authentication_success]
wazuh_rules: ["5902", "5904", "60109", "60110", "60154", "60160"]
keywords: [new user, user added, account created, group membership, administrators, domain admins, sudoers, useradd, net user]
severity_hint: high
---
# Suspicious creation or modification of privileged accounts

A new account is created, or an account is added to a privileged group (Administrators,
Domain Admins, sudo/wheel), outside an approved change process. It is a classic persistence technique.

## Indicators
- Windows events 4720 (account created), 4728/4732/4756 (added to a privileged group), 4738 (account changed).
- On Linux: `useradd`, `usermod -aG sudo`, changes to `/etc/passwd`, `/etc/group` or `/etc/sudoers`.
- Creation outside business hours or by an account that does not normally manage users.

## Triage
1. Identify who made the change (source account), from which host and at what time.
2. Check whether a ticket or change request justifies it.
3. Review the subsequent activity of the new or modified account (logons, access).

## Containment
1. If it is not authorized, disable the created account or revert the group change.
2. Investigate and, if appropriate, disable the account that made the change.
3. Review other accounts created or modified by the same actor in the last 48 hours.

## Eradication and recovery
1. Reset the credentials of the privileged accounts involved.
2. Review GPOs, tasks and SSH keys added by the actor to remove additional persistence.

## Escalation
- Escalate to tier 2 if the account belongs to a domain administration group or if there is no justification.

## False positives
- Accounts created by the identity team during onboarding (validate against the ticket).

---
id: data-exfiltration
title: Possible data exfiltration or anomalous outbound traffic
mitre: [T1041, T1048, T1048.003, T1567, T1071.004]
tactics: [Exfiltration, Command and Control]
wazuh_groups: [firewall, suricata, ids, dns, proxy, netflow, data_exfiltration]
wazuh_rules: ["86601", "4151", "87702"]
keywords: [exfiltration, large upload, outbound traffic, dns tunneling, cloud storage, data transfer, suricata, beaconing, unusual destination]
severity_hint: high
---
# Possible data exfiltration or anomalous outbound traffic

Unusual outbound data volume, connections to non-corporate cloud storage services, DNS
tunnels or beaconing patterns towards external destinations.

## Indicators
- Suricata or firewall alerts with large outbound transfers or low-reputation destinations.
- DNS queries with long, random subdomains (possible DNS tunnel) or at a very high rate.
- Uploads to file-sharing services outside the user's usual working hours.

## Triage
1. Quantify the volume transferred, the destination and the duration of the connection.
2. Identify the process and the user on the source host that generate the traffic.
3. Determine which data could be involved (file servers, databases accessed).
4. Check the reputation of the destination and whether other hosts contact it.

## Containment
1. Block the destination on the firewall, proxy and DNS.
2. Isolate the source host if the unauthorized transfer is confirmed.
3. Suspend the credentials of the user involved for the duration of the investigation.

## Eradication and recovery
1. Remove the tool or malware used for the exfiltration and its persistence.
2. Review DLP and egress rules to restrict unapproved destinations.

## Escalation
- Escalate to IR, legal and data protection if there are signs that personal or confidential data left the organization.

## False positives
- Cloud backups, corporate file synchronization or software updates.

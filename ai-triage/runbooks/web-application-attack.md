---
id: web-application-attack
title: Web application attack (SQLi, XSS, path traversal, RCE)
mitre: [T1190, T1505.003, T1059.004]
tactics: [Initial Access, Persistence]
wazuh_groups: [web, accesslog, attack, sql_injection, xss, web_scan, modsecurity]
wazuh_rules: ["31101", "31103", "31104", "31105", "31106", "31151", "31152", "31171"]
keywords: [web attack, sql injection, sqli, xss, cross site scripting, path traversal, lfi, rce, webshell, user agent, http 500, scanner]
severity_hint: medium
---
# Web application attack

HTTP requests with SQL injection, XSS, path traversal or command injection patterns, or
webshell access, detected in the web server or WAF logs.

## Indicators
- Rules 31103/31104 (SQLi / XSS), 31106 (attack with a 200 response), 31151/31152 (mass scanning).
- Parameters with `UNION SELECT`, `../`, `<script>`, `;wget`, or tool user agents (sqlmap, nikto).
- The user agent or other request fields may contain text manipulated by the attacker.

## Triage
1. Determine whether the attack succeeded: response code (200 versus 403/404), response size and 500 errors.
2. Check whether the source IP is running a broad scan or an attack targeting a specific URL.
3. Review the application and database logs in the same time window.
4. Look for new files in the docroot (possible webshell) with integrity (FIM) alerts.

## Containment
1. Block the source IP on the WAF or firewall if the attack persists.
2. If there are signs of success (200 response with data, webshell), put the affected service behind the WAF or isolate the server.
3. Enable virtual patching rules on the WAF for the exploited vector.

## Eradication and recovery
1. Fix the vulnerability in the code or update the affected component.
2. Remove webshells and review exposed database credentials.

## Escalation
- Escalate if there is evidence of successful exploitation, data access or command execution.

## False positives
- Authorized vulnerability scanners (validate the IP and the testing window).

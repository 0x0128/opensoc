---
id: suspicious-powershell
title: Suspicious PowerShell execution
mitre: [T1059.001, T1027, T1105, T1140]
tactics: [Execution, Defense Evasion]
wazuh_groups: [windows, sysmon, sysmon_event1, powershell, windows_powershell]
wazuh_rules: ["91802", "91816", "91837", "92057", "92213"]
keywords: [powershell, encodedcommand, enc, base64, iex, invoke-expression, downloadstring, bypass, hidden window, amsi]
severity_hint: high
---
# Suspicious PowerShell execution

PowerShell invoked with parameters typical of obfuscation or code download: `-EncodedCommand`,
`-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, `DownloadString`, `IEX`, or AMSI being disabled.

## Indicators
- Command line with long base64, string concatenation or unusual escape characters.
- Anomalous parent process: Office, a browser, `wmiprvse.exe`, `mshta.exe` or services.
- Outbound network connections from the `powershell.exe` process right after it starts.

## Triage
1. Decode the `-EncodedCommand` content in an isolated environment and analyze what it does.
2. Review the process tree (parent, children) and the user running it.
3. Check Script Block Logging (event 4104) to see the deobfuscated script.
4. Check the network destinations contacted and the files written by the process.

## Containment
1. If it downloads or runs remote code, isolate the host and block the domains or IPs involved.
2. Terminate the process and its children, taking a memory dump first if possible.
3. Temporarily disable the account if its credentials may be compromised.

## Eradication and recovery
1. Remove the associated persistence (scheduled tasks, WMI subscriptions, Run keys).
2. Apply Constrained Language Mode, AppLocker/WDAC and enable Script Block Logging across the fleet.

## Escalation
- Escalate to tier 2 if the script downloads payloads, steals credentials or repeats on several hosts.

## False positives
- Management tools (SCCM, Intune, IT scripts) that use `-EncodedCommand` legitimately: validate signature and origin.

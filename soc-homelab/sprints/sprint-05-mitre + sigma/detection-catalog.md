# Detection Catalog — Sprint 5

| ID | Detection | Log Source | MITRE ATT&CK | Sigma Status | Wazuh Validation |
|---|---|---|---|---|---|
| SIG-001 | PowerShell Encoded Command Execution | Sysmon Event ID 1 | T1059.001 | Validated | Pending |
| SIG-002 | Certutil Download Activity | Sysmon Event ID 1 | T1105 | Pending | Pending |
| SIG-003 | Suspicious Scheduled Task Creation | Sysmon Event ID 1 | T1053.005 | Pending | Pending |
| SIG-004 | Suspicious DNS Query | Sysmon Event ID 22 | T1071.004 | Pending | Pending |
| SIG-005 | Suspicious Network Connection | Sysmon Event ID 3 | T1071.001 | Pending | Pending |
| SIG-006 | Suspicious File Creation in Temp Directory | Sysmon Event ID 11 | T1105 | Pending | Pending |

## SIG-001 — PowerShell Encoded Command Execution

**Telemetry:**  
Windows Sysmon Event ID 1 — Process Creation.

**Detection logic:**  
Detects `powershell.exe` executions where the command line contains `-enc`, `-encodedcommand`, or `-e`.

**Risk rationale:**  
Encoded PowerShell commands can conceal malicious execution and are commonly associated with script-based attacks.

**Validation status:**  
The rule was validated with Sigma CLI and returned zero errors, zero condition errors and zero issues.

**Next validation step:**  
Generate a harmless encoded PowerShell command on the Windows Server and confirm the resulting Sysmon Event ID 1 in Wazuh.
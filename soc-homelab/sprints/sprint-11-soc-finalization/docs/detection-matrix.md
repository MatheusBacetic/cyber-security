# Detection Matrix

## Status Definitions

| Status | Meaning |
|---|---|
| Validated | The detection was tested in the lab and produced the expected telemetry, rule match, alert, or response behavior. |
| Tuning pending | Telemetry was confirmed, but the detection requires additional filtering or correlation before it should be treated as a final high-confidence alert. |

## Matrix

| Rule ID | Detection | Tactic | Technique | MITRE | Telemetry Source | Status |
|---:|---|---|---|---|---|---|
| 100200 | Sysmon DNS query | Command and Control | DNS | T1071.004 | Sysmon Operational | Validated |
| 100220 | PowerShell Encoded Command | Execution | PowerShell | T1059.001 | Sysmon Operational / Windows telemetry | Validated |
| 100222 | Defender detection for certutil activity | Command and Control | Ingress Tool Transfer | T1105 | Microsoft Defender / Windows Security telemetry | Validated |
| 100223 | Scheduled Task telemetry | Execution / Persistence | Scheduled Task/Job | T1053 | Windows Security / Sysmon telemetry | Tuning pending |
| 100230 | Windows Command Shell | Execution | Windows Command Shell | T1059.003 | Sysmon Operational / Windows process telemetry | Validated |
| 100231 | SSH password guessing correlation | Credential Access, Lateral Movement | Password Guessing, SSH | T1110.001, T1021.004 | Ubuntu SSH/auth logs | Validated |
| 100232 | Active Response base rule | N/A | N/A | N/A | Wazuh alert pipeline / Active Response trigger | Validated |
| 100240 | AD user account creation | Persistence | Create Account: Domain Account | T1136.002 | AD Monitor JSONL / Windows Security Event Log | Validated |
| 100250 | Custom C SSH Honeypot brute force | Credential Access, Lateral Movement | Password Guessing, SSH | T1110.001, T1021.004 | Honeypot JSONL | Validated |

## Notes

- The matrix only includes detections implemented and documented in the lab.
- Rule `100223` remains tuning pending because scheduled task telemetry can be noisy without additional context.
- Rule `100232` is listed as an Active Response base rule. It supports response workflow validation rather than mapping directly to a MITRE technique.
- MITRE ATT&CK mapping is used to explain analyst relevance, not to imply complete enterprise coverage.

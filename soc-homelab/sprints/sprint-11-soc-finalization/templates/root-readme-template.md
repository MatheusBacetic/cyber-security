# SOC Home Lab

## Objective

This repository documents a professional SOC Home Lab built for Cyber Security / SOC Analyst portfolio development.

The project demonstrates the complete analyst workflow: telemetry collection, detection engineering, threat hunting, MITRE ATT&CK mapping, incident response, Active Response, Active Directory monitoring, and custom honeypot integration.

## Architecture Summary

| Asset | Hostname | IP | Role |
|---|---|---:|---|
| Windows Server 2022 Domain Controller | `WIN-SERVER-DC` | `192.168.100.10` | AD, Windows Security logs, Sysmon, AD monitoring |
| Wazuh Manager Ubuntu Server 24.04 | `adv-consultoria` | `192.168.100.30` | SIEM, Indexer, Dashboard, rules, archives, response |
| Kali Linux | `kali` | `192.168.100.20` | Controlled attacker simulation |
| Arch Linux Honeypot Sensor | `ARCH-HONEY-01` | `192.168.100.40` | Custom C SSH Honeypot + IDS |
| Windows Client | Domain joined endpoint | Internal lab network | Endpoint activity |

## Main Capabilities

- Wazuh Manager, Indexer, and Dashboard
- Windows Wazuh Agent deployment
- Wazuh Agent on a dedicated honeypot sensor
- Sysmon telemetry collection
- Wazuh archives for raw-event hunting
- Sigma CLI usage
- MITRE ATT&CK mapping
- Custom Wazuh local rules
- Active Response with nftables
- Python Active Directory Security Monitor integration
- C SSH Honeypot + IDS integration
- JSONL telemetry export and Wazuh collection
- Incident documentation and rollback validation

## Sprint List

| Sprint | Topic |
|---|---|
| Sprint 01 | Wazuh core installation |
| Sprint 02 | Windows Agent |
| Sprint 03 | Sysmon |
| Sprint 04 | Detection Engineering and Threat Hunting |
| Sprint 05 | MITRE + Sigma |
| Sprint 06 | Dashboards |
| Sprint 07 | Attack Simulation |
| Sprint 08 | Active Response |
| Sprint 09 | Active Directory Security Integration |
| Sprint 10 | Custom C SSH Honeypot SIEM Integration |
| Sprint 11 | SOC Finalization |

## Detection Highlights

| Rule ID | Detection | MITRE | Status |
|---:|---|---|---|
| 100200 | Sysmon DNS query | T1071.004 | Validated |
| 100220 | PowerShell Encoded Command | T1059.001 | Validated |
| 100222 | Defender detection for certutil activity | T1105 | Validated |
| 100223 | Scheduled Task telemetry | T1053 | Tuning pending |
| 100230 | Windows Command Shell | T1059.003 | Validated |
| 100231 | SSH password guessing correlation | T1110.001, T1021.004 | Validated |
| 100232 | Active Response base rule | N/A | Validated |
| 100240 | AD user account creation | T1136.002 | Validated |
| 100250 | Custom C SSH Honeypot brute force | T1110.001, T1021.004 | Validated |

## MITRE ATT&CK Coverage

The lab maps validated activity to MITRE ATT&CK techniques including:

- `T1059.001` - PowerShell
- `T1059.003` - Windows Command Shell
- `T1071.004` - DNS
- `T1105` - Ingress Tool Transfer
- `T1053` - Scheduled Task/Job
- `T1110.001` - Password Guessing
- `T1021.004` - SSH
- `T1136.002` - Create Account: Domain Account

## Simulated Incidents

- Windows Command Shell execution
- Kali service discovery against the Domain Controller
- SSH password guessing
- Active Directory account creation
- Honeypot SSH brute force detection

## How to Explain This in an Interview

This project is not only a dashboard deployment. It demonstrates how a SOC analyst thinks through the full workflow:

1. Collect telemetry from Windows, Linux, AD, and custom tools.
2. Build and validate detections.
3. Investigate raw events in archives.
4. Map behavior to MITRE ATT&CK.
5. Respond with controlled containment.
6. Validate rollback.
7. Document incidents clearly.

The strongest differentiator is the custom C SSH Honeypot + IDS integration. The honeypot was kept as a separate tool, exported to JSONL with Python, collected by Wazuh Agent, and detected with a custom Wazuh rule.

## Scope

This is a controlled home lab and portfolio project. It does not claim production-grade coverage or enterprise scale.

AWS/cloud telemetry is not part of the final scope due to academic account limitations and project focus.

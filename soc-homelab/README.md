````markdown
# SOC Home Lab

A practical Security Operations Center lab built to simulate real SOC workflows: telemetry collection, detection engineering, threat hunting, incident investigation, active response, Active Directory monitoring, and custom security-tool integration.

This project was developed as a cybersecurity portfolio focused on SOC Analyst / Cyber Security Junior roles.

## Objectives

- Build hands-on experience with SIEM operations.
- Collect and investigate endpoint telemetry.
- Create and validate detections using Wazuh rules.
- Map detections to MITRE ATT&CK.
- Perform controlled attack simulations in an isolated lab.
- Document investigation and response workflows.
- Demonstrate a portfolio project that is explainable in technical interviews.

## Environment

| Asset | Hostname | IP Address | Role |
|---|---|---:|---|
| Windows Server 2022 | `WIN-SERVER-DC` | `192.168.100.10` | Domain Controller, Sysmon and Windows telemetry source |
| Ubuntu Server 24.04 | `adv-consultoria` | `192.168.100.30` | Wazuh Manager, Indexer and Dashboard |
| Kali Linux | `kali` | `192.168.100.20` | Controlled attacker simulation |
| Arch Linux | `ARCH-HONEY-01` | `192.168.100.40` | SSH Honeypot sensor and Linux telemetry source |
| Windows Client | Domain joined endpoint | Internal lab network | Windows endpoint telemetry source |

## Architecture

```text
                              ┌──────────────────────────────┐
                              │ Wazuh SIEM                   │
                              │ Ubuntu Server                │
                              │ 192.168.100.30               │
                              │                              │
                              │ Manager / Indexer / Dashboard│
                              └──────────────▲───────────────┘
                                             │
                           Wazuh Agent / log telemetry
                                             │
          ┌──────────────────┬───────────────┼──────────────────┐
          │                  │               │                  │
          ▼                  ▼               ▼                  ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐ ┌──────────────┐
│ WIN-SERVER-DC    │ │Windows Client│ │ ARCH-HONEY-01    │ │ Kali Linux   │
│ 192.168.100.10   │ │Domain Joined │ │ 192.168.100.40   │ │192.168.100.20│
│                  │ │              │ │                  │ │              │
│ Sysmon           │ │Windows Logs  │ │ C SSH Honeypot   │ │ Controlled   │
│ Security Events  │ │              │ │ JSONL Exporter   │ │ Simulations  │
│ AD Monitor       │ │              │ │ nftables Response│ │              │
└──────────────────┘ └──────────────┘ └────────▲─────────┘ └──────┬───────┘
                                                │                  │
                                                └──── TCP/2222 ────┘
````

## Core Capabilities

| Capability                  | Implementation                                        |
| --------------------------- | ----------------------------------------------------- |
| SIEM                        | Wazuh Manager, Indexer and Dashboard                  |
| Windows telemetry           | Wazuh Agent and Sysmon                                |
| Linux telemetry             | Wazuh Agent on `ARCH-HONEY-01`                        |
| Threat hunting              | Wazuh archives and raw event investigation            |
| Detection engineering       | Custom Wazuh local rules                              |
| Detection validation        | `wazuh-logtest` and controlled simulations            |
| MITRE ATT&CK                | Technique mapping for validated detections            |
| Active response             | nftables source-IP blocking                           |
| Active Directory monitoring | Python AD Security Monitor integration                |
| Custom telemetry            | C SSH Honeypot + incremental Python JSONL exporter    |
| Incident response           | Investigation, containment and rollback documentation |

## Detection Coverage

|  Rule ID | Detection                                | MITRE ATT&CK         | Status         |
| -------: | ---------------------------------------- | -------------------- | -------------- |
| `100200` | Sysmon DNS query                         | T1071.004            | Validated      |
| `100220` | PowerShell Encoded Command               | T1059.001            | Validated      |
| `100222` | Defender detection for certutil activity | T1105                | Validated      |
| `100223` | Scheduled Task telemetry                 | T1053                | Tuning pending |
| `100230` | Windows Command Shell execution          | T1059.003            | Validated      |
| `100231` | SSH password guessing correlation        | T1110.001, T1021.004 | Validated      |
| `100232` | Active Response base rule                | N/A                  | Validated      |
| `100240` | Active Directory user account creation   | T1136.002            | Validated      |
| `100250` | Custom C SSH Honeypot brute force        | T1110.001, T1021.004 | Validated      |

## Custom Honeypot SIEM Integration

A custom SSH honeypot and IDS written in C was integrated into Wazuh.

```text
Kali controlled connections
→ C SSH Honeypot on TCP/2222
→ IDS brute force threshold
→ logs/alerts.log
→ incremental Python exporter
→ honeypot-wazuh.jsonl
→ Wazuh Agent
→ JSON decoder / base rule 86600
→ custom rule 100250
→ Wazuh alert level 12
→ nftables blacklist response
```

The honeypot runs on a dedicated Arch Linux sensor rather than on the Wazuh Manager. This separates exposed sensor logic from the centralized SIEM platform.

## Incident Simulations

| Scenario                                         | Telemetry Source              | Detection Outcome                   |
| ------------------------------------------------ | ----------------------------- | ----------------------------------- |
| Windows Command Shell execution                  | Sysmon Process Creation       | Wazuh rule `100230`                 |
| Kali service discovery against Domain Controller | Sysmon Network Connection     | Investigated through Wazuh archives |
| SSH password guessing                            | Linux SSH authentication logs | Wazuh rule `100231`                 |
| Active Directory user creation                   | Python AD Monitor JSONL       | Wazuh rule `100240`                 |
| SSH honeypot brute force                         | Custom C IDS JSONL            | Wazuh rule `100250`, level 12       |

## Project Structure

```text
soc-homelab/
├── sprints/
│   ├── sprint-01-wazuh-core/
│   ├── sprint-02-windows-agent/
│   ├── sprint-03-sysmon/
│   ├── sprint-04-detection-engineering-threat-hunting/
│   ├── sprint-05-mitre + sigma/
│   ├── sprint-06-dashboards/
│   ├── sprint-07-attack-simulation/
│   ├── sprint-08-active-response/
│   ├── sprint-09-ad-security-integration/
│   ├── sprint-10-honeypot/
│   └── sprint-11-soc-finalization/
└── README.md
```

Each sprint contains its own documentation, configurations, evidence, detection logic, and validation results.

## Key Technical Decisions

* **Wazuh was selected as the SIEM** because it provides endpoint agents, log collection, rule-based detection, MITRE ATT&CK mapping, active response, file integrity monitoring, and security configuration assessment in one platform.
* **Sysmon was deployed on the Domain Controller** to provide high-value Windows process, network, file, DNS, and registry telemetry.
* **Wazuh archives were enabled** to support raw event investigation and threat hunting beyond generated alerts.
* **Custom detections were implemented as child rules** when events were already classified by a Wazuh base rule.
* **The honeypot produces JSON Lines telemetry** so custom IDS events can be collected and analyzed by the SIEM without rewriting the original C application.
* **nftables was used for active response** because it allows source-IP blocking directly on the Linux sensor.
* **AWS integration was intentionally excluded** from this lab due to limitations of the academic AWS account. The lab scope remained focused on validated on-premises SOC workflows rather than an incomplete cloud integration.

## Skills Demonstrated

* Wazuh deployment and administration
* Windows endpoint monitoring
* Sysmon telemetry analysis
* Linux endpoint monitoring
* SIEM log ingestion
* Detection engineering
* Wazuh rule development
* MITRE ATT&CK mapping
* Sigma rule validation
* Threat hunting with raw logs
* Incident triage and investigation
* Active response with nftables
* Active Directory security monitoring
* Python automation
* C network security development
* Structured JSON logging
* Technical documentation for security operations

## Interview Summary

> I built an isolated SOC Home Lab using Wazuh, Windows Server Active Directory, Sysmon, Kali Linux, and an Arch Linux honeypot sensor. I collected Windows and Linux telemetry, created and validated custom Wazuh rules, mapped detections to MITRE ATT&CK, investigated raw events through Wazuh archives, simulated controlled attack activity, and implemented active response with nftables. I also integrated a custom SSH honeypot and IDS written in C into the SIEM using an incremental Python JSONL exporter and a custom Wazuh detection rule.

## Scope and Limitations

This is an isolated VirtualBox lab intended for learning, detection validation, and portfolio development.

* Attack simulations were controlled and performed only inside the lab.
* The honeypot was exposed only to the internal lab network.
* AWS/cloud telemetry was not integrated because the available academic account had service and permission limitations.
* Scheduled Task detection remains documented as tuning pending rather than presented as fully validated.

## Documentation

The final project documentation is available in:

* `sprints/sprint-11-soc-finalization/docs/final-architecture.md`
* `sprints/sprint-11-soc-finalization/docs/asset-and-log-inventory.md`
* `sprints/sprint-11-soc-finalization/docs/detection-matrix.md`
* `sprints/sprint-11-soc-finalization/docs/incident-summary.md`
* `sprints/sprint-11-soc-finalization/docs/soc-operations-playbook.md`
* `sprints/sprint-11-soc-finalization/docs/interview-walkthrough.md`

```
```

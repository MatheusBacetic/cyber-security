# Final Architecture

## Overview

The final SOC Home Lab uses separated systems for SIEM operations, Windows endpoint telemetry, attacker simulation, and honeypot sensing. This separation makes the lab easier to explain, safer to operate, and closer to a real SOC environment.

## Assets

| Asset | Hostname | IP |
|---|---|---:|
| Windows Server 2022 Domain Controller | `WIN-SERVER-DC` | `192.168.100.10` |
| Wazuh Manager Ubuntu Server 24.04 | `adv-consultoria` | `192.168.100.30` |
| Kali Linux | `kali` | `192.168.100.20` |
| Arch Linux Honeypot Sensor | `ARCH-HONEY-01` | `192.168.100.40` |
| Windows Client | Domain joined endpoint | Internal lab network |

## Logical Diagram

```text
                           Internal Lab Network

        +----------------------+                  +----------------------+
        | Kali Linux           |                  | Windows Client       |
        | kali                 |                  | Domain joined        |
        | 192.168.100.20       |                  | Internal lab network |
        | Attacker simulation  |                  | Endpoint activity    |
        +----------+-----------+                  +----------+-----------+
                   |                                         |
                   | Controlled tests                        | Domain activity
                   |                                         |
                   v                                         v
        +----------------------+                  +----------------------+
        | ARCH-HONEY-01        |                  | WIN-SERVER-DC        |
        | 192.168.100.40       |                  | 192.168.100.10       |
        | C SSH Honeypot + IDS |                  | AD + Windows logs    |
        | Wazuh Agent          |                  | Sysmon + Wazuh Agent |
        +----------+-----------+                  +----------+-----------+
                   |                                         |
                   | Honeypot JSONL                          | Security Event Log
                   | Wazuh Agent TCP/1514                    | Sysmon Operational
                   |                                         | AD Monitor JSONL
                   +------------------+----------------------+
                                      |
                                      v
                         +-------------------------+
                         | Wazuh Manager           |
                         | adv-consultoria         |
                         | 192.168.100.30          |
                         | Manager + Indexer       |
                         | Dashboard + Archives    |
                         | Rules + Active Response |
                         +-------------------------+
```

## Separation of Functions

| Function | System | Reason |
|---|---|---|
| SIEM management | `adv-consultoria` | Centralized collection, rules, alerting, archives, and dashboard access |
| Windows endpoint telemetry | `WIN-SERVER-DC` and Windows Client | Domain activity, Windows Security events, Sysmon telemetry, and AD monitoring |
| Attacker simulation | `kali` | Controlled offensive activity for validation only |
| Honeypot sensor | `ARCH-HONEY-01` | Exposed custom service separated from the SIEM manager |

## Telemetry Flows

Windows telemetry:

```text
Windows Security Event Log
        |
Sysmon Operational Log
        |
AD Monitor JSONL
        |
Wazuh Agent on WIN-SERVER-DC
        |
Wazuh Manager
        |
Archives, rules, alerts, dashboard
```

Ubuntu/Wazuh server telemetry:

```text
Ubuntu SSH/auth logs
        |
Wazuh local collection
        |
Correlation rule 100231
        |
Active Response base rule 100232
        |
nftables temporary containment
```

Honeypot telemetry:

```text
Kali controlled TCP/2222 attempts
        |
C SSH Honeypot + IDS on ARCH-HONEY-01
        |
logs/alerts.log
        |
Incremental Python exporter
        |
logs/honeypot-wazuh.jsonl
        |
Wazuh Agent on ARCH-HONEY-01
        |
Wazuh JSON decoder
        |
Rule 100250
        |
Wazuh alert
```

## Why the Honeypot Does Not Run on the Wazuh Manager

The honeypot runs on `ARCH-HONEY-01` instead of the Wazuh Manager to keep exposed services and response logic away from the central SIEM platform.

This design avoids placing a deliberately reachable SSH-like service on the same host that stores alerts, rules, archives, and dashboard components. It also keeps nftables blacklist behavior isolated to the sensor and makes the architecture easier to reason about during incident response.

## Scope Limitations

This lab is not an enterprise production deployment. It is a controlled portfolio environment designed to show the full SOC workflow: log collection, detection engineering, validation, hunting, response, rollback, and documentation.

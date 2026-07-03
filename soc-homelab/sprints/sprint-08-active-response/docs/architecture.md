# Architecture — Sprint 9 Active Response

## Overview

Sprint 9 extends the SOC Home Lab from detection-only capability to automated containment.

The Ubuntu Server acts as the Wazuh Manager and also as the enforcement point for the response. SSH authentication failures are collected locally, correlated by Wazuh, and handled through nftables.

## Components

| Component | IP Address | Responsibility |
|---|---:|---|
| Kali Linux | `192.168.100.20` | Controlled SSH password-guessing simulation source |
| Ubuntu Server | `192.168.100.30` | Wazuh Manager, SSH service, nftables enforcement point |
| Windows Server 2022 | `192.168.100.10` | Domain Controller and protected asset |
| Wazuh Analysis Engine | Local | Parses logs and evaluates detection rules |
| Wazuh Active Response | Local | Executes the containment script |
| nftables | Local | Temporarily drops traffic from detected source IPs |

## Architecture Flow

```text
Kali Linux
192.168.100.20
        |
        | Repeated SSH authentication failures
        v
Ubuntu Server
192.168.100.30
        |
        | sshd logs
        v
Wazuh Logcollector
        |
        | Native SSH rules + custom correlation
        v
Rule 100231
Possible SSH Password Guessing
        |
        | Active Response
        v
nftables-temp-block.sh
        |
        | Add source IP with timeout
        v
nftables blocked_ips set
        |
        | Drop traffic from attacker IP
        v
Kali SSH access blocked temporarily
# Asset and Log Inventory

## Inventory

| Asset | IP | Operating System | Role | Agent | Log Sources | Collection Method |
|---|---:|---|---|---|---|---|
| `WIN-SERVER-DC` | `192.168.100.10` | Windows Server 2022 | Domain Controller and Windows telemetry source | Wazuh Agent | Security Event Log, Sysmon Operational, AD Monitor JSONL | Windows EventChannel collection and Wazuh localfile JSON collection |
| Windows Client | Internal lab network | Windows client OS | Domain joined endpoint | Wazuh Agent where applicable | Windows endpoint activity | Wazuh Agent and domain telemetry visibility |
| `adv-consultoria` | `192.168.100.30` | Ubuntu Server 24.04 | Wazuh Manager, Indexer, Dashboard, archives, rules, and active response | Local Wazuh components | Ubuntu SSH/auth logs, Wazuh alerts, Wazuh archives | Wazuh manager local collection and indexed archives |
| `kali` | `192.168.100.20` | Kali Linux | Controlled attacker simulation | None | Controlled test activity | Observed indirectly through target logs and Wazuh alerts |
| `ARCH-HONEY-01` | `192.168.100.40` | Arch Linux | Dedicated C SSH Honeypot + IDS sensor | Wazuh Agent | Honeypot JSONL, honeypot connection logs, honeypot alert logs | Wazuh localfile JSON collection |

## Required Log Sources

| Log Source | Location / Channel | Primary Use |
|---|---|---|
| Security Event Log | Windows Security channel | Account activity, authentication, and native Windows audit evidence |
| Sysmon Operational | Microsoft-Windows-Sysmon/Operational | Process, network, DNS, and command execution telemetry |
| AD Monitor JSONL | Custom Python AD Security Monitor output | Structured Active Directory security events |
| Honeypot JSONL | `logs/honeypot-wazuh.jsonl` on `ARCH-HONEY-01` | Structured custom honeypot alerts |
| Ubuntu SSH/auth logs | Ubuntu authentication logs on Wazuh server | SSH password guessing correlation and response validation |
| Wazuh archives | Wazuh archive indices / `archives.json` | Threat hunting and raw event confirmation |

## Collection Notes

- Native Windows telemetry remains the primary forensic source for Windows activity.
- Sysmon enriches Windows visibility with process, DNS, and command execution details.
- JSONL is used for custom telemetry because Wazuh can decode structured JSON events cleanly.
- Wazuh archives are used to confirm raw events even when alert rules are tuned or not promoted.
- Kali is intentionally not monitored as an endpoint; it is the controlled source of simulated activity.

## Limitations

The inventory reflects the completed lab state. It does not include cloud telemetry, EDR products, or production identity integrations beyond the documented Active Directory lab.

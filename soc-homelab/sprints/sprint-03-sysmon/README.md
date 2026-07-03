# Sprint 03 — Sysmon Integration

## Objective

Implement Microsoft Sysmon on the Windows Server Domain Controller and integrate its telemetry with Wazuh to improve endpoint visibility and enable advanced detection engineering capabilities.

---

## Environment

| Component | Version |
|----------|---------|
| Windows Server | 2022 |
| Wazuh Manager | 4.14 |
| Ubuntu Server | 24.04 |
| Sysmon | Sysinternals |
| Configuration | SwiftOnSecurity Sysmon Config |

---

## Architecture

```
Windows Server
      │
      │ Sysmon
      ▼
Microsoft-Windows-Sysmon/Operational
      │
      ▼
Wazuh Agent
      │
      ▼
Wazuh Manager
      │
      ▼
Indexer
      │
      ▼
Dashboard
```

---

## Objectives Achieved

- Installed Microsoft Sysmon
- Applied SwiftOnSecurity configuration
- Enabled EventChannel collection on Wazuh Agent
- Validated event generation
- Validated event ingestion
- Validated OpenSearch indexing
- Confirmed MITRE ATT&CK mapping

---

## Key Event IDs

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 11 | File Creation |
| 22 | DNS Query |

---

## Technologies

- Wazuh
- Sysmon
- Windows Event Log
- OpenSearch
- MITRE ATT&CK

---

## Skills Demonstrated

- Endpoint Telemetry
- SIEM Integration
- Windows Logging
- Threat Detection
- Security Monitoring
- Event Correlation
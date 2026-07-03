# Integration Architecture

## Objective

Integrate the existing Python Active Directory Security Monitor with the SOC Home Lab without replacing native Windows Security Event Logs.

The Windows Security Event Log remains the primary source of evidence. The custom monitor acts as an additional enrichment layer that detects and summarizes relevant AD security activity.

## Architecture

```text
Windows Server 2022 Domain Controller
192.168.100.10
        |
        | Windows Security Event Log
        v
AD Security Monitor (Python)
C:\AD-Monitor\monitor.py
        |
        | Human-readable alerts
        v
C:\AD-Monitor\logs\alerts.log
        |
        | JSON Lines conversion
        v
C:\AD-Monitor\wazuh_export.py
        |
        | Structured telemetry
        v
C:\AD-Monitor\logs\wazuh-ad-monitor.jsonl
        |
        | Wazuh Agent localfile collection
        v
Wazuh Manager
192.168.100.30
        |
        +--> Wazuh Archives
        +--> Wazuh Alerts
        +--> Wazuh Dashboard

        Security Event ID 4720
→ Python AD Monitor
→ JSONL exporter
→ Wazuh Agent
→ Wazuh JSON decoder
→ Wazuh Rule 100240
→ Wazuh alert
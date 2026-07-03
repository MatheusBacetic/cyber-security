
# Sprint 04 - Detection Engineering & Threat Hunting

## Objective

Develop detection engineering skills using Wazuh and Sysmon while performing threat hunting over Windows telemetry.

## Environment

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Windows Server 2022
- Sysmon (SwiftOnSecurity configuration)
- Ubuntu Server 24.04

## Activities

### Detection Engineering

Implemented a custom Wazuh detection rule for suspicious DNS queries.

Rule ID:

100200

Detected domains:

- pastebin.com
- githubusercontent.com
- ngrok.io
- ngrok-free.app
- duckdns.org
- trycloudflare.com

MITRE ATT&CK

- T1071.004

---

### Threat Hunting

Performed hunting using Sysmon telemetry indexed by Wazuh.

Covered telemetry:

- Event ID 1 – Process Creation
- Event ID 3 – Network Connection
- Event ID 11 – File Creation
- Event ID 22 – DNS Query

---

### Event ID 3 Investigation

During testing, the custom Event ID 3 rule matched successfully in `wazuh-logtest`, but did not generate alerts in the live pipeline.

Instead of forcing a workaround, the issue was documented and Event ID 3 hunting was performed using the `wazuh-archives-*` index.

This reflects a real troubleshooting workflow rather than an artificial success.

## Skills Practiced

- Detection Engineering
- Threat Hunting
- Sysmon
- Wazuh Rules
- MITRE ATT&CK Mapping
- OpenSearch Queries
- SOC Investigation Workflow
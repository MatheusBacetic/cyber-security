
# Sysmon Event ID 3 - Detection Engineering Troubleshooting

## Overview

During Sprint 4, the goal was to develop a custom Wazuh detection rule for Sysmon **Event ID 3 (Network Connection)** in order to detect outbound PowerShell HTTPS connections.

Although the event was successfully generated and collected by Wazuh, the custom rule did not generate alerts in the live pipeline despite matching successfully in `wazuh-logtest`.

Instead of forcing a workaround, the investigation was documented and the hunting strategy was changed to use indexed telemetry from `wazuh-archives-*`.

---

# Detection Objective

Detect outbound PowerShell HTTPS connections using Sysmon Event ID 3.

Expected detection:

- Process: `powershell.exe`
- Destination Port: `443`
- MITRE ATT&CK
  - T1059.001 – PowerShell
  - T1071.001 – Application Layer Protocol: Web Protocols

---

# Validation Performed

The investigation followed the complete telemetry pipeline.

## 1. Sysmon Validation

Confirmed that Sysmon generated Event ID 3 correctly.

Verified using:

- Windows Event Viewer
- Microsoft-Windows-Sysmon/Operational

Status:

✅ Successful

---

## 2. Wazuh Agent

Confirmed that the Wazuh Agent collected and forwarded the event.

Status:

✅ Successful

---

## 3. Manager Archive

Confirmed that the event was received by the Wazuh Manager.

Evidence:

- `/var/ossec/logs/archives/archives.json`

Observed fields:

```text
decoder.name: windows_eventchannel
providerName: Microsoft-Windows-Sysmon
eventID: 3
image: powershell.exe
destinationPort: 443
destinationIp: <external IPv6>
```

Status:

✅ Successful

---

## 4. Rule Validation

A custom rule was created for:

- Event ID 3
- PowerShell
- Destination Port 443

The rule matched successfully when tested using:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Result:

```text
Rule matched

Level 10

Alert to be generated
```

Status:

✅ Successful

---

## 5. Live Pipeline Validation

Although the same event was received by the manager, no alert was generated inside:

```text
alerts.json
```

Status:

❌ Failed

---

# Additional Investigation

To verify that the problem was not caused by local rules, a canary rule was created.

Canary Rule:

```text
Rule ID: 100999
```

Parent Rule:

```text
5402
```

The canary rule successfully generated alerts in the live pipeline.

Result:

- local_rules.xml loaded correctly
- Custom rules working correctly
- Wazuh Manager processing local rules

Status:

✅ Successful

---

# Root Cause Analysis

The investigation demonstrated the following:

| Component | Status |
|-----------|--------|
| Sysmon Event Generated | ✅ |
| Wazuh Agent | ✅ |
| EventChannel Decoder | ✅ |
| Archives.json | ✅ |
| Field Normalization | ✅ |
| wazuh-logtest | ✅ |
| Local Rules | ✅ |
| Live XML Alert | ❌ |

The exact reason for the mismatch between `wazuh-logtest` and the live alert pipeline was not determined during this sprint.

However, all available evidence indicates that the telemetry itself was correctly ingested.

---

# Technical Decision

Rather than spending additional time forcing a live XML alert, the investigation shifted to Threat Hunting using indexed telemetry.

The `wazuh-archives-*` index was enabled and used as the primary data source for Sysmon Event ID 3 hunting.

This approach more closely reflects real SOC workflows, where analysts frequently investigate raw telemetry that does not necessarily generate alerts.

---

# Threat Hunting Example

Example Event ID 3 observed during the lab:

| Field | Value |
|-------|-------|
| Process | `C:\Windows\System32\OpenSSH\ssh.exe` |
| Destination IP | `192.168.100.30` |
| Destination Port | `22` |
| Protocol | TCP |
| Initiated | True |

This event represents an outbound SSH connection from the Windows Server to the Ubuntu Wazuh server and was successfully identified using the `wazuh-archives-*` index.

---

# Lessons Learned

- Detection engineering requires validating the complete telemetry pipeline.
- Successful `wazuh-logtest` execution does not always guarantee identical live pipeline behavior.
- Raw telemetry stored in `wazuh-archives-*` is valuable for Threat Hunting, even when alerts are not generated.
- Troubleshooting should be documented transparently instead of masking unresolved behavior.
- Threat Hunting complements detection engineering by allowing analysts to investigate events beyond generated alerts.

---

# Outcome

**Sprint Status:** Completed

The Event ID 3 investigation successfully validated Sysmon telemetry collection and demonstrated a practical Threat Hunting workflow using Wazuh and OpenSearch.
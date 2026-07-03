# Validation

## Local Validation

Verified:

- Sysmon service
- Windows Event Viewer
- Event IDs

Example:

- Event ID 1
- Event ID 22

---

## Wazuh Validation

Confirmed:

- Wazuh Agent connected.
- Sysmon channel monitored.
- Events indexed.

---

## OpenSearch Validation

Executed:

```bash
curl -k -u admin:<password> \
https://localhost:9200/wazuh-alerts-4.x-*/_search?q=Microsoft-Windows-Sysmon
```

Result:

- 121 indexed Sysmon events.

---

## Detection Validation

Observed detections including:

Rule:

```
92213
```

Description:

```
Executable file dropped in folder commonly used by malware
```

MITRE ATT&CK

```
T1105
Ingress Tool Transfer
```
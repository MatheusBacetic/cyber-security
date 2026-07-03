
# Threat Hunting Queries

## Overview

This document contains the primary hunting queries used during Sprint 4.

All hunts were performed using Sysmon telemetry indexed by Wazuh/OpenSearch.

---

# Hunt 01 — PowerShell Process Creation

## Purpose

Identify PowerShell execution.

## Query

```text
data.win.system.eventID:1
AND data.win.eventdata.image:*powershell.exe*
```

## Fields

- image
- commandLine
- parentImage
- parentCommandLine
- user
- processGuid

---

# Hunt 02 — PowerShell Network Connections

## Purpose

Identify outbound PowerShell network activity.

## Query

```text
data.win.system.eventID:3
AND data.win.eventdata.image:*powershell.exe*
```

## Fields

- image
- destinationIp
- destinationPort
- protocol
- processGuid

---

# Hunt 03 — PowerShell HTTPS

## Purpose

Identify PowerShell communicating over HTTPS.

## Query

```text
data.win.system.eventID:3
AND data.win.eventdata.image:*powershell.exe*
AND data.win.eventdata.destinationPort:443
```

---

# Hunt 04 — SSH Connections

## Purpose

Identify SSH client activity.

## Query

```text
data.win.system.eventID:3
AND data.win.eventdata.destinationPort:22
```

## Example Result

```
Image

C:\Windows\System32\OpenSSH\ssh.exe

Destination

192.168.100.30

Protocol

TCP
```

## Evidence

The Wazuh indexed log view below shows repeated SSH authentication failures handled by `sshd`, including failed password attempts for user `math` from source `192.168.100.20`.

![SSH failed password evidence](screenshots/ssh-failed-password-evidence.svg)

---

# Hunt 05 — Suspicious DNS Queries

## Purpose

Identify DNS requests to suspicious domains.

## Query

```text
data.win.system.eventID:22
AND (
data.win.eventdata.queryName:*pastebin.com*
OR
data.win.eventdata.queryName:*githubusercontent.com*
OR
data.win.eventdata.queryName:*ngrok*
OR
data.win.eventdata.queryName:*duckdns*
OR
data.win.eventdata.queryName:*trycloudflare*
)
```

## MITRE

- T1071.004

---

# Hunt 06 — File Creation

## Purpose

Identify files created by PowerShell.

## Query

```text
data.win.system.eventID:11
AND data.win.eventdata.image:*powershell.exe*
```

## Fields

- image
- targetFilename
- processGuid
- user

---

# Hunt 07 — Process Tree Analysis

## Purpose

Reconstruct process execution chains.

## Query

```text
data.win.system.eventID:1
```

## Fields

- image
- commandLine
- parentImage
- parentCommandLine
- processGuid
- parentProcessGuid
- user

## Investigation Workflow

1. Locate the suspicious process.
2. Review the command line.
3. Identify the parent process.
4. Correlate using Process GUID.
5. Search for related Event ID 3 network connections.
6. Search for related Event ID 11 file creation.
7. Build the complete execution timeline.

---

# Skills Practiced

- Detection Engineering
- Threat Hunting
- Sysmon Analysis
- Process Investigation
- Network Investigation
- DNS Investigation
- Process Tree Analysis
- MITRE ATT&CK Mapping
- Wazuh/OpenSearch Queries

````markdown
# Integration Architecture

## Objective

Integrate the existing SSH Honeypot + IDS written in C with the SOC Home Lab using Wazuh as the centralized SIEM.

The architecture separates the attacker simulation environment, honeypot sensor, and SIEM platform. This prevents the Wazuh Manager from also becoming the exposed honeypot endpoint and reflects a more realistic SOC design.

## Components

| Component | Hostname | IP Address | Responsibility |
|---|---|---:|---|
| Kali Linux | kali | 192.168.100.20 | Controlled attacker simulation |
| Honeypot Sensor | ARCH-HONEY-01 | 192.168.100.40 | Runs the custom C SSH Honeypot + IDS |
| Wazuh Manager | adv-consultoria | 192.168.100.30 | Centralized log collection, detection, alerting, and investigation |
| Windows Server Domain Controller | WIN-SERVER-DC | 192.168.100.10 | Active Directory environment |

## Logical Architecture

```text
┌──────────────────────────────────────────────┐
│ Kali Linux                                   │
│ IP: 192.168.100.20                           │
│ Role: Controlled attacker simulation         │
└───────────────────────┬──────────────────────┘
                        │
                        │ TCP/2222
                        │ Controlled repeated connections
                        ▼
┌──────────────────────────────────────────────┐
│ ARCH-HONEY-01                                │
│ IP: 192.168.100.40                           │
│ Role: Custom Linux Honeypot Sensor            │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │ SSH Honeypot + IDS in C                │  │
│  │ - Simulated SSH banner                 │  │
│  │ - Connection logging                   │  │
│  │ - Brute force threshold detection      │  │
│  │ - nftables blacklist response          │  │
│  └────────────────────┬───────────────────┘  │
│                       │                      │
│                       ▼                      │
│  logs/connections.log                         │
│  logs/alerts.log                              │
│                       │                      │
│                       ▼                      │
│  honeypot_export.py                           │
│                       │                      │
│                       ▼                      │
│  logs/honeypot-wazuh.jsonl                    │
│                       │                      │
│                       ▼                      │
│  Wazuh Agent                                  │
└───────────────────────┬──────────────────────┘
                        │
                        │ Wazuh Agent communication
                        │ TCP/1514
                        ▼
┌──────────────────────────────────────────────┐
│ Wazuh Manager                                 │
│ IP: 192.168.100.30                            │
│                                              │
│ - Receives custom JSONL telemetry             │
│ - Decodes events using JSON decoder           │
│ - Matches base rule 86600                     │
│ - Applies custom child rule 100250            │
│ - Generates level 12 SOC alert                │
└──────────────────────────────────────────────┘
````

## Data Flow

1. Kali Linux performs controlled TCP connection attempts against the honeypot sensor on port `2222`.
2. The C honeypot accepts the connection and returns a simulated SSH banner.
3. Each connection is written to `logs/connections.log`.
4. After five attempts from the same source IP, the IDS creates a brute force event in `logs/alerts.log`.
5. The honeypot inserts a source-IP drop rule in the nftables `blacklist` chain.
6. `honeypot_export.py` reads only new entries from `logs/alerts.log`.
7. The exporter appends one structured JSON event per alert to `logs/honeypot-wazuh.jsonl`.
8. The Wazuh Agent monitors the JSONL file through a `<localfile>` configuration.
9. The Wazuh Agent sends the event to the Wazuh Manager over TCP port `1514`.
10. Wazuh decodes the JSON event and matches base rule `86600`.
11. Custom child rule `100250` identifies the honeypot brute force event.
12. Wazuh generates a level 12 alert mapped to MITRE ATT&CK.

## Network Controls

The honeypot sensor uses an nftables default deny policy.

The controlled simulation host is explicitly allowed to access the honeypot:

| Source         | Destination    | Protocol | Port | Purpose                        |
| -------------- | -------------- | -------- | ---: | ------------------------------ |
| 192.168.100.20 | 192.168.100.40 | TCP      | 2222 | Controlled honeypot simulation |
| 192.168.100.40 | 192.168.100.30 | TCP      | 1514 | Wazuh Agent event delivery     |
| 192.168.100.40 | 192.168.100.30 | TCP      | 1515 | Wazuh Agent enrollment         |

After the brute force threshold is reached, the source IP is inserted into the nftables `blacklist` chain.

## Architecture Decisions

### Dedicated Honeypot Sensor

The honeypot runs on `ARCH-HONEY-01` instead of the Wazuh Manager.

This separation prevents an exposed service and custom nftables response logic from sharing the same host as the SIEM platform. It also makes the lab architecture closer to a real environment where sensors, endpoints, and central monitoring platforms have separate responsibilities.

### JSON Lines for SIEM Ingestion

The C application continues writing its original text logs. A separate Python exporter converts only IDS alerts into JSON Lines.

This preserves the original project while creating structured telemetry suitable for SIEM ingestion.

### Incremental Export

The exporter stores its read position in:

```text
logs/.honeypot_export.offset
```

This prevents previously processed alerts from being exported repeatedly and allows the JSONL file to receive only new IDS events.

### Parent/Child Wazuh Rule Model

The JSON event is decoded by Wazuh and initially matches base rule `86600`.

Custom rule `100250` is implemented as a child rule using:

```xml
<if_sid>86600</if_sid>
```

This ensures the detection is evaluated after the JSON event has been decoded and classified by the Wazuh ruleset.

## Detection Output

The final Wazuh alert includes:

| Field        | Value                |
| ------------ | -------------------- |
| Agent        | ARCH-HONEY-01        |
| Source IP    | 192.168.100.20       |
| Alert Type   | brute_force          |
| Attempts     | 5                    |
| Rule ID      | 100250               |
| Severity     | 12                   |
| MITRE ATT&CK | T1110.001, T1021.004 |

## Security Value

This integration demonstrates that a custom security tool written in C can become a structured telemetry source for a centralized SOC platform without requiring a full rewrite of the original application.

```
```

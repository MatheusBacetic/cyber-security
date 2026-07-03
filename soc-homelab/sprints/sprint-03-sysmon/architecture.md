# Architecture

```
                   Windows Server 2022

                 +---------------------+
                 |      Sysmon         |
                 +---------------------+
                           │
                           │
        Microsoft-Windows-Sysmon/Operational
                           │
                           ▼
                    Wazuh Agent
                           │
                     TCP 1514
                           │
                           ▼
                   Wazuh Manager
                           │
                           ▼
                   Wazuh Indexer
                           │
                           ▼
                 OpenSearch Dashboard
```

## Data Flow

1. Sysmon captures endpoint activity.
2. Events are written to the Windows Event Log.
3. Wazuh Agent reads the EventChannel.
4. Events are sent to the Wazuh Manager.
5. Wazuh decodes and correlates the events.
6. Alerts are indexed in OpenSearch.
7. Events become available for SOC analysts.
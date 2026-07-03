# Implementation

## Sysmon Installation

- Installed Sysmon64.
- Accepted EULA.
- Applied SwiftOnSecurity configuration.

## Wazuh Configuration

Added EventChannel collection:

```xml
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```

Restarted the Wazuh Agent.

## Validation

Confirmed:

- Sysmon service running.
- Event generation.
- EventChannel collection.
- Wazuh Agent communication.
- Event indexing.
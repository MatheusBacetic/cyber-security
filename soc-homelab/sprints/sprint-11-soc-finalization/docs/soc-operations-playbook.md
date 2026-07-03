# SOC Operations Playbook

## Purpose

This playbook documents the operational workflow used in the SOC Home Lab for alert triage, validation, investigation, containment, rollback, and incident documentation.

## Triage Workflow

1. Validate the alert in Wazuh.
2. Identify the affected host, source IP, user, process, command line, and rule ID.
3. Confirm the raw event in Wazuh archives.
4. Review related events around the same timestamp.
5. Map the behavior to MITRE ATT&CK.
6. Decide whether containment is required.
7. Apply containment only when the source and impact are understood.
8. Validate rollback.
9. Document the incident, evidence, result, and limitations.

## Alert Validation

Confirm:

- Rule ID
- Rule level
- Agent name
- Source IP
- Destination host
- User
- Process name
- Command line
- MITRE technique
- Timestamp
- Related raw event

## Archive Investigation

Wazuh archives are used to validate raw telemetry behind an alert and to hunt for related activity that may not have generated an alert.

Useful commands:

```bash
sudo grep '"rule":{"id":"100230"' /var/ossec/logs/alerts/alerts.json
sudo grep 'WIN-SERVER-DC' /var/ossec/logs/archives/archives.json
sudo grep '192.168.100.20' /var/ossec/logs/archives/archives.json
sudo grep 'honeypot' /var/ossec/logs/archives/archives.json
```

## Agent Validation

List connected agents:

```bash
sudo /var/ossec/bin/agent_control -l
```

Confirm that expected systems are active:

- `WIN-SERVER-DC`
- `ARCH-HONEY-01`
- Wazuh Manager local components

## Rule Testing

Use `wazuh-logtest` before relying on a custom rule:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Validation goals:

- Confirm JSON decoding.
- Confirm expected fields are present.
- Confirm the custom rule matches.
- Confirm MITRE metadata appears when configured.

## Active Response and Containment

For SSH password guessing validation, nftables was used for temporary containment.

Inspect the ruleset:

```bash
sudo nft list ruleset
```

Containment principles:

- Block only the confirmed source IP.
- Avoid blocking localhost.
- Avoid blocking the Domain Controller.
- Prefer timeout-based rules.
- Confirm service recovery after rollback.

## Rollback

Rollback must be validated after every containment action.

Examples:

- Remove a temporary nftables block.
- Confirm SSH or service connectivity is restored.
- Remove temporary AD test accounts.
- Confirm Wazuh agents remain connected.

## Documentation Checklist

Record:

- Incident ID
- Detection name
- Rule ID
- Affected host
- Source IP
- User or process
- MITRE technique
- Evidence location
- Response action
- Rollback result
- Known limitations

## Professional Notes

Not every event should become a high-severity alert. The lab intentionally documents tuning pending status where telemetry exists but confidence is not high enough for final alerting.

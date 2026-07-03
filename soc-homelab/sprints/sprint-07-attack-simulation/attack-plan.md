# Attack Plan — SIM-003 SSH Password Guessing from Kali Linux

## Simulation ID

SIM-003

## Objective

Validate whether the SOC Home Lab can detect, correlate, investigate, and document repeated SSH authentication failures originating from Kali Linux against the Ubuntu Wazuh Manager.

## Environment

| Component | Details |
|---|---|
| Attack source | Kali Linux |
| Source IP | `192.168.100.20` |
| Target endpoint | Ubuntu Wazuh Manager |
| Target hostname | `adv-consultoria` |
| Target IP | `192.168.100.30` |
| Target service | SSH — TCP/22 |
| SIEM | Wazuh |
| Log source | Ubuntu `sshd` logs via journald |
| Execution environment | Isolated VirtualBox SOC Home Lab |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Lateral Movement | Remote Services: SSH | T1021.004 |

## Controlled Activity

Kali Linux generated repeated failed SSH authentication attempts against the Ubuntu Wazuh Manager using the local account `math` and intentionally incorrect passwords.

The simulation was limited to a small number of controlled attempts and did not use password lists, automated brute-force tools, valid credentials, exploitation, persistence, payload delivery, or post-authentication activity.

## Expected Telemetry

| Source | Expected Event | Investigation Value |
|---|---|---|
| Ubuntu SSH daemon | Failed password log | Captures source IP, target user, source port, and SSH authentication result. |
| Wazuh native rule | Rule `5760` — `sshd: authentication failed.` | Detects each failed SSH authentication event. |
| Wazuh custom correlation rule | Rule `100231` | Detects repeated failures from the same source IP. |
| Wazuh Alerts | Correlated high-severity alert | Centralizes the suspected password-guessing activity for investigation. |

## Detection Goal

Confirm that repeated failed SSH authentication attempts from Kali Linux are visible in Wazuh and correlated into a high-severity alert.

Key investigation fields:

- `data.srcip`
- `data.dstuser`
- `data.srcport`
- `agent.name`
- `rule.id`
- `rule.level`
- `rule.frequency`
- `rule.mitre.id`
- `full_log`

## Detection Logic

```xml
<rule id="100232" level="5">
  <if_sid>5760</if_sid>
  <description>SIM-003: SSH authentication failure observed</description>
  <group>attack_simulation,ssh_auth_failure,</group>
</rule>

<rule id="100231" level="12" frequency="4" timeframe="120">
  <if_matched_sid>100232</if_matched_sid>
  <same_source_ip />
  <description>SIM-003: Possible SSH password guessing activity from same source IP</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>attack_simulation,ssh_bruteforce,credential_access,</group>
</rule>
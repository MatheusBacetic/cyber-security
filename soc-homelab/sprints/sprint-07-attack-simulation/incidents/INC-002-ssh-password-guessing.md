# INC-002 — Suspected SSH Password Guessing from Kali Linux

## Incident Classification

| Field | Value |
|---|---|
| Incident ID | INC-002 |
| Simulation ID | SIM-003 |
| Status | Closed — Authorized Security Simulation |
| Severity | High |
| Detection Rule | Wazuh Rule `100231` |
| Alert Level | `12` |
| MITRE ATT&CK | `T1110.001 — Brute Force: Password Guessing` |
| Additional MITRE Context | `T1021.004 — Remote Services: SSH` |
| Source Host | Kali Linux |
| Source IP | `192.168.100.20` |
| Target Host | `adv-consultoria` |
| Target IP | `192.168.100.30` |
| Target Service | SSH — TCP/22 |
| Target User | `math` |
| Detection Time | `2026-07-02 18:09:53 UTC` |

## Alert Summary

Wazuh generated a high-severity correlated alert after repeated SSH authentication failures from the same source IP.

The activity originated from Kali Linux at `192.168.100.20` and targeted the Ubuntu Wazuh Manager at `192.168.100.30`. The repeated failures targeted the local user account `math` over SSH.

The custom correlation rule detected four authentication failures from the same source IP within a 120-second window and generated a level 12 alert.

## Detection Evidence

| Artifact | Observed Value |
|---|---|
| Wazuh Rule ID | `100231` |
| Rule Description | `SIM-003: Possible SSH password guessing activity from same source IP` |
| Alert Level | `12` |
| Rule Frequency | `4` |
| Source IP | `192.168.100.20` |
| Target User | `math` |
| Target Host | `adv-consultoria` |
| Target Service | SSH |
| Native SSH Rule | `5760 — sshd: authentication failed.` |
| MITRE Technique | `T1110.001 — Password Guessing` |
| Additional MITRE Technique | `T1021.004 — SSH` |
| Log Source | `journald` |
| Decoder | `sshd` |

## Timeline

| Time (UTC) | Event |
|---|---|
| 18:09:38 | Failed SSH authentication attempt from `192.168.100.20` against user `math`. |
| 18:09:42 | Additional failed SSH authentication attempt from the same source IP. |
| 18:09:49 | Additional failed SSH authentication attempt from the same source IP. |
| 18:09:53 | Fourth failed authentication attempt triggered Wazuh correlation Rule `100231`. |
| 18:09:54 | High-severity Wazuh alert indexed in `wazuh-alerts-*`. |

## Analyst Investigation

The alert was reviewed in Wazuh using the source IP `192.168.100.20`, target user `math`, SSH daemon logs, and correlated alert metadata.

Individual failed authentication events were first detected by the native Wazuh SSH rule `5760`. The repeated pattern was then correlated by custom Rule `100231`, which identified four failures from the same source IP within 120 seconds.

The activity resembled password-guessing behavior because multiple failed SSH logins were directed at the same target account from one internal source.

## Assessment

The source IP was identified as Kali Linux within the isolated SOC Home Lab network. The activity was an authorized simulation designed to validate SSH authentication monitoring, event correlation, alert prioritization, and SOC investigation workflow.

The attempts used intentionally incorrect passwords. No valid credentials were used, no authentication succeeded, and no post-authentication activity occurred.

## Impact Assessment

No compromise occurred.

- No successful SSH session was established.
- No files were accessed or modified.
- No credentials were obtained.
- No privilege escalation occurred.
- No persistence was created.
- No lateral movement occurred.
- No external communication or payload delivery occurred.

## Final Disposition

**Closed — Authorized Security Simulation**

No containment or remediation was required because the activity was generated intentionally inside the isolated lab.

## Recommended Production Response

If this alert occurred in a production environment, the SOC analyst should:

1. Validate whether the source IP belongs to an approved administrator, monitoring platform, VPN range, or jump host.
2. Review authentication attempts against other users and hosts from the same source IP.
3. Check whether any successful SSH login occurred after the failed attempts.
4. Investigate the source endpoint for unauthorized tooling or suspicious processes.
5. Consider temporarily blocking the source IP if the activity is unapproved.
6. Review SSH hardening controls, including key-based authentication, MFA, account lockout policies, rate limiting, and network access restrictions.

## Lessons Learned

- Native Wazuh SSH rules detect individual authentication failures but may produce low-severity alerts.
- Correlation logic is necessary to identify repeated behavior that resembles password guessing.
- Source-IP correlation reduced alert noise and increased detection priority.
- MITRE ATT&CK mapping improved incident classification and investigation context.
- The final level 12 alert demonstrated how SOC detection engineering can transform raw authentication logs into actionable security alerts.

## Evidence References

- `evidence/16-kali-internal-routing-fixed.png`
- `evidence/17-kali-ssh-failed-auth-attempts.png`
- `evidence/18-wazuh-ssh-authentication-alerts.png`
- `evidence/19-kali-repeated-ssh-attempts.png`
- `evidence/20-wazuh-possible-ssh-password-guessing.png`
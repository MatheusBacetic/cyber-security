# Interview Walkthrough

## 30-Second Explanation

This is a SOC Home Lab built to demonstrate the full analyst workflow. I deployed Wazuh, collected Windows and Linux telemetry, added Sysmon, created custom Wazuh rules, mapped detections to MITRE ATT&CK, validated alerts with controlled attacks, used archives for hunting, tested Active Response with nftables, integrated an Active Directory monitor in Python, and connected a custom C SSH honeypot to Wazuh through JSONL telemetry.

## 2-Minute Explanation

The project is designed as a realistic junior SOC portfolio lab. The Wazuh Manager runs on Ubuntu and receives telemetry from a Windows Server Domain Controller and a dedicated Arch Linux honeypot sensor.

On Windows, I collected native Security Event Logs and Sysmon telemetry, then built detections for command shell execution, encoded PowerShell, DNS activity, certutil-related Defender alerts, scheduled task telemetry, and Active Directory account creation. I used Wazuh archives to validate raw events and avoid relying only on dashboard alerts.

For response, I implemented an Active Response workflow with nftables to temporarily block SSH password guessing sources. I also validated rollback so the response was reversible.

The final part of the lab integrated a custom SSH Honeypot + IDS written in C. Instead of rewriting it, I created a Python exporter that converts its alerts into JSONL. Wazuh collects that JSONL file through an agent and rule `100250` detects brute force activity.

The main difference is that this is not just a dashboard project. It includes collection, detection engineering, threat hunting, incident response, active response, AD integration, and a custom C honeypot integrated into the SIEM.

## Technical Deep Dive

The lab uses four main systems:

- `WIN-SERVER-DC` at `192.168.100.10` for Active Directory, Windows Security Event Logs, Sysmon, and AD monitor telemetry.
- `adv-consultoria` at `192.168.100.30` for Wazuh Manager, Indexer, Dashboard, rules, alerts, archives, and Active Response.
- `kali` at `192.168.100.20` for controlled attacker simulation.
- `ARCH-HONEY-01` at `192.168.100.40` for the custom C SSH Honeypot + IDS.

Detection engineering was done with local Wazuh rules and validated through controlled simulations. The rules include Windows execution behavior, SSH password guessing, AD account creation, and honeypot brute force detection.

The lab also uses Wazuh archives as a hunting layer. This is important because alerts show what matched a rule, while archives show the raw telemetry that supports or challenges the alert.

For the honeypot, the architecture keeps the exposed SSH-like service away from the Wazuh Manager. The C honeypot writes local logs, the Python exporter converts new alerts to JSONL, the Wazuh Agent collects the JSONL file, and the Wazuh Manager applies rule `100250`.

## Common Questions and Answers

### Why did you use Wazuh?

Wazuh is accessible for a home lab but still gives practical SOC concepts: agents, log collection, rules, alerts, archives, MITRE mapping, dashboards, and Active Response.

### What is the strongest part of the project?

The strongest part is the complete workflow. I did not stop at installing a dashboard. I created telemetry sources, validated detections, investigated raw archives, documented incidents, tested response, rolled back changes, and integrated custom tools.

### How did you avoid false positives?

I separated validated detections from tuning pending telemetry. For example, scheduled task telemetry was confirmed, but it remains tuning pending because scheduled tasks can be noisy without more context.

### Why use MITRE ATT&CK?

MITRE helps describe what behavior the alert represents. It makes the detection easier to explain during triage and helps connect technical logs to attacker behavior.

### Why did the honeypot run on a separate host?

The honeypot is intentionally exposed to controlled connection attempts. Running it on a separate sensor avoids exposing the Wazuh Manager and keeps SIEM operations separate from deception and blocking logic.

### What would you improve next?

I would improve tuning, add more realistic alert severity decisions, expand Windows endpoint coverage, and add safe cloud telemetry only when the account and permissions support it properly.

### Is this production ready?

No. It is a controlled SOC Home Lab for portfolio and learning. It demonstrates practical workflows and engineering decisions, but production environments require scale planning, secure secrets handling, change control, retention policies, and operational monitoring.

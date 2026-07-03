# Sprint 7 — Attack Simulation

## Objective

Execute controlled adversary-behavior simulations in the SOC Home Lab, generate endpoint telemetry, validate Wazuh detections, map observed activity to MITRE ATT&CK, and document each exercise as a mini SOC incident.

## Scope

All simulations are executed exclusively inside the isolated VirtualBox laboratory environment. The exercises are designed to be safe, non-destructive, and focused on detection engineering and investigation.

## Sprint Structure

* `attack-plan.md`: documents the simulation scope, objective, expected telemetry, and MITRE ATT&CK mapping.
* `detections/`: documents the detection logic and validation results.
* `incidents/`: contains incident-style investigation reports.
* `evidence/`: contains screenshots and collected validation evidence.

## First Simulation

The first controlled simulation will validate detection of Windows Command Shell execution.

* MITRE ATT&CK Technique: T1059.003 — Windows Command Shell
* Expected telemetry source: Sysmon Event ID 1 — Process Creation
* Detection platform: Wazuh
* Endpoint: WIN-SERVER-DC

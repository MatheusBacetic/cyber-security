# Sprint 5 — Sigma Detection Engineering

## Overview

This sprint focuses on creating, validating and documenting Sigma detection rules using Windows Sysmon telemetry collected by Wazuh.

The objective is to build portable detection content mapped to MITRE ATT&CK and validate each rule against controlled events generated in the SOC Home Lab.

## Scope

- Sigma rule development
- Sigma CLI validation
- Windows Sysmon Event ID 1, 3, 11 and 22
- Wazuh hunting queries
- MITRE ATT&CK mapping
- Detection tuning and false-positive analysis
- Controlled attack simulation and validation

## Detection Lifecycle

```text
Threat Technique
      ↓
Telemetry Requirement
      ↓
Sigma Rule
      ↓
Sigma Validation
      ↓
Controlled Event Generation
      ↓
Wazuh Investigation
      ↓
Tuning and Documentation
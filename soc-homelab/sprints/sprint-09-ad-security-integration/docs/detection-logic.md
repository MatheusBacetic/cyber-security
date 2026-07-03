# Detection Logic

## Overview

The integration adds structured telemetry from the custom Python AD Security Monitor to Wazuh.

The monitor produces human-readable alerts locally. A separate exporter converts these alerts into JSON Lines, which are collected by the Wazuh Agent.

## JSONL Schema

Example:

```json
{
  "integration": "ad-security-monitor",
  "schema_version": "1.0",
  "timestamp": "2026-07-03T13:36:53.652550+00:00",
  "event_id": 4720,
  "event_name": "Usuário criado",
  "event_type": "account_created",
  "severity": "HIGH",
  "target_user": "soc.test.0703063652",
  "group": "-",
  "actor": "Administrator"
}
---
platform: "letsdefend"
category: "blueteam"
title: "SIEM Alert Investigation"
date: 2024-09-14
difficulty: "Easy"
tags:
  - Blue Team
  - LetsDefend
  - SIEM
  - SOC
  - Alert Triage
---

# **SIEM Alert Investigation**

> Mock writeup — LetsDefend Easy challenge performing alert triage on SIEM-generated security events.

## Scenario

Multiple SIEM alerts triggered for a single host. Triage the alerts, determine true/false positives, and escalate as needed.

## Analysis

Reviewed alert context, correlated source/destination IPs with threat intelligence, and checked process execution logs.

## Key Findings

- Brute-force alert: True positive — 200+ failed login attempts from external IP
- Malware detection: True positive — Mimikatz execution detected via hash match
- DNS tunneling alert: False positive — legitimate cloud backup service
- Created incident report and recommended IP block and credential reset

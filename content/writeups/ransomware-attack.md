---
platform: "cyberdefenders"
category: "blueteam"
title: "Ransomware Attack Investigation"
date: 2024-08-20
difficulty: "Hard"
tags:
  - Blue Team
  - CyberDefenders
  - DFIR
  - Ransomware
  - Memory Forensics
  - Volatility
---

# **Ransomware Attack Investigation**

> Mock writeup — CyberDefenders Hard challenge performing digital forensics on a ransomware incident.

## Scenario

A company was hit by ransomware. Investigate the memory dump, disk image, and event logs to reconstruct the attack timeline.

## Analysis

Used Volatility for memory forensics, analyzing process trees, network connections, and injected code. Cross-referenced with Windows Event Logs.

## Key Findings

- Initial access via RDP brute-force (Event ID 4625 flood followed by 4624)
- Attacker disabled Windows Defender via PowerShell (Event ID 5001)
- Ransomware binary injected into svchost.exe process
- Shadow copies deleted using vssadmin before encryption

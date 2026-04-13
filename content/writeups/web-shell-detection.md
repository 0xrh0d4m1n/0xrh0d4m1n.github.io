---
platform: "letsdefend"
category: "blueteam"
title: "Web Shell Detection"
date: 2024-06-30
difficulty: "Medium"
tags:
  - Blue Team
  - LetsDefend
  - Web Shell
  - Log Analysis
  - IIS
  - DFIR
---

# **Web Shell Detection**

> Mock writeup — LetsDefend Medium challenge detecting and analyzing a web shell on a compromised IIS server.

## Scenario

Security monitoring detected unusual outbound connections from a web server. Investigate access logs, file system artifacts, and network traffic.

## Analysis

Correlated IIS access logs with Sysmon events to identify the initial upload vector and subsequent command execution through the web shell.

## Key Findings

- Web shell uploaded via exploited file upload form (unrestricted file type)
- ASPX web shell executed whoami, net user, and systeminfo commands
- Attacker established persistence via scheduled task
- Data exfiltration through base64-encoded POST requests to external IP

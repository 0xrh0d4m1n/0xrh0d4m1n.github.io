---
platform: "htb"
category: "redteam"
title: "Hospital"
date: 2024-04-10
difficulty: "Medium"
tags:
  - HackTheBox
  - Writeup
  - Windows
  - Web
  - File Upload
  - GhostScript
---

# **Hospital**

> Mock writeup — HackTheBox Medium machine exploiting file upload bypass and GhostScript vulnerability on a Windows/Linux dual-boot environment.

## Reconnaissance

Hospital management web application with file upload functionality. The server runs both a Linux web server and a Windows host.

## Exploitation

Bypassed file upload filters to upload a PHP webshell. Escalated through a GhostScript CVE for Linux root, then pivoted to the Windows host via shared credentials.

## Privilege Escalation

Exploited XAMPP misconfiguration on the Windows side for SYSTEM access.

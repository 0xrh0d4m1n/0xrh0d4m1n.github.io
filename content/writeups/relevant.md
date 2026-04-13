---
platform: "thm"
category: "redteam"
title: "Relevant"
date: 2024-07-22
difficulty: "Medium"
tags:
  - TryHackMe
  - Writeup
  - Windows
  - SMB
  - PrintSpoofer
---

# **Relevant**

> Mock writeup — TryHackMe Medium room with SMB share enumeration leading to IIS webshell upload and PrintSpoofer privilege escalation.

## Reconnaissance

Multiple open ports including SMB and IIS web server. Anonymous SMB access revealed credentials.

## Exploitation

Uploaded an ASPX webshell to an SMB share mounted as a virtual directory in IIS.

## Privilege Escalation

Used PrintSpoofer to escalate from IIS service account to SYSTEM through SeImpersonatePrivilege.

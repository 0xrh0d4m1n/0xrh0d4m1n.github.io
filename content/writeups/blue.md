---
platform: "thm"
category: "redteam"
title: "Blue"
date: 2024-01-20
difficulty: "Easy"
tags:
  - TryHackMe
  - Writeup
  - Windows
  - EternalBlue
  - SMB
---

# **Blue**

> Mock writeup — TryHackMe Easy room exploiting the infamous MS17-010 EternalBlue vulnerability.

## Reconnaissance

Windows 7 machine with SMB service exposed. Nmap scripts confirmed MS17-010 vulnerability.

## Exploitation

Used Metasploit's `exploit/windows/smb/ms17_010_eternalblue` module for initial access with SYSTEM privileges.

## Post-Exploitation

Dumped password hashes, cracked user credentials, and found flags across the filesystem.

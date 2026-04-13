---
platform: "htb"
category: "redteam"
title: "Clicker"
date: 2024-03-01
difficulty: "Medium"
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - PHP
  - NFS
---

# **Clicker**

> Mock writeup — HackTheBox Medium machine with a PHP web game exploiting parameter tampering and NFS misconfiguration.

## Reconnaissance

Discovered a PHP-based clicker game with NFS shares exposed.

## Exploitation

Parameter tampering via CRLF injection to elevate user role to admin, followed by PHP code injection through exported file functionality.

## Privilege Escalation

NFS no_root_squash misconfiguration combined with a setuid binary allowed privilege escalation to root.

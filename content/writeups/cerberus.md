---
platform: "htb"
category: "redteam"
title: "Cerberus"
date: 2023-10-14
difficulty: "Hard"
tags:
  - HackTheBox
  - Writeup
  - Windows
  - Linux
  - Icinga
  - Active Directory
---

# **Cerberus**

> Mock writeup — HackTheBox Hard machine involving Icinga Web exploitation and Active Directory pivoting.

## Reconnaissance

Icinga monitoring platform running on a Linux host with Active Directory integration to a Windows domain controller.

## Exploitation

Exploited CVE-2022-24716 (arbitrary file read) and CVE-2022-24715 (RCE) in Icinga Web 2 to gain initial foothold on the Linux host.

## Pivot & Privilege Escalation

Extracted SSSD credentials to pivot into the Active Directory domain. Abused ADCS certificate templates for domain admin.

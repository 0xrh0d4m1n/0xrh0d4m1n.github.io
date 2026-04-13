---
platform: "vulnhub"
category: "redteam"
title: "Kioptrix Level 1"
date: 2023-09-10
difficulty: "Easy"
tags:
  - VulnHub
  - Writeup
  - Linux
  - Apache
  - Samba
---

# **Kioptrix Level 1**

> Mock writeup — VulnHub Easy machine exploiting outdated Apache mod_ssl and Samba services.

## Reconnaissance

Legacy Linux system running Apache 1.3 with mod_ssl and Samba 2.2.

## Exploitation

Exploited the OpenFuck (CVE-2002-0082) vulnerability in mod_ssl for remote code execution as apache user.

## Alternative Path

Samba trans2open overflow (CVE-2003-0201) also provided root access directly.

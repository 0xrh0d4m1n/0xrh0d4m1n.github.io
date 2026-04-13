---
platform: "thm"
category: "redteam"
title: "Overpass"
date: 2024-06-10
difficulty: "Easy"
tags:
  - TryHackMe
  - Writeup
  - Linux
  - Web
  - Cookie Manipulation
  - Cron
---

# **Overpass**

> Mock writeup — TryHackMe Easy room exploiting broken authentication and cron job hijacking.

## Reconnaissance

Custom password manager web application with a vulnerable login mechanism.

## Exploitation

The login page used client-side cookie authentication. Setting the `SessionToken` cookie bypassed authentication entirely.

## Privilege Escalation

Found SSH private key in admin panel, then hijacked a cron job that fetched a script via HTTP to gain root.

---
platform: "htb"
category: "redteam"
title: "Codify"
date: 2024-02-15
difficulty: "Easy"
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - Node.js
  - vm2
---

# **Codify**

> Mock writeup — HackTheBox Easy machine exploiting a Node.js sandbox escape via vm2 vulnerability.

## Reconnaissance

Target machine running a web application built with Node.js that allows users to test JavaScript code in a sandboxed environment.

## Exploitation

The vm2 library used for sandboxing had a known vulnerability (CVE-2023-37466) allowing sandbox escape through prototype pollution.

## Post-Exploitation

Credential reuse from a SQLite database led to SSH access and privilege escalation via a vulnerable backup script.

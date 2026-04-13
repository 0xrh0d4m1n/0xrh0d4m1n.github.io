---
platform: "htb"
category: "redteam"
title: "Appsanity"
date: 2024-05-20
difficulty: "Hard"
tags:
  - HackTheBox
  - Writeup
  - Windows
  - Web
  - .NET
  - SSRF
---

# **Appsanity**

> Mock writeup — HackTheBox Hard machine exploiting SSRF and .NET deserialization in a medical application.

## Reconnaissance

Multi-service Windows environment running a .NET healthcare application with internal microservices.

## Exploitation

Chained an SSRF vulnerability in the PDF report generator with an internal API endpoint to achieve remote code execution via .NET deserialization.

## Privilege Escalation

Extracted credentials from application config, abused DLL sideloading in a privileged service.

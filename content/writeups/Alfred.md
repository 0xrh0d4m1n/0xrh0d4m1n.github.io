---
platform: "thm"
category: "redteam"
title: "Alfred"
date: 2024-03-15
difficulty: "Easy"
tags:
  - TryHackMe
  - Writeup
  - Windows
  - Jenkins
  - Token Impersonation
---

# **Alfred**

> Mock writeup — TryHackMe Easy room exploiting Jenkins CI/CD default credentials and Windows token impersonation.

## Reconnaissance

Jenkins server on port 8080 with default admin credentials.

## Exploitation

Executed a Groovy reverse shell script through the Jenkins Script Console to gain initial foothold.

## Privilege Escalation

Used Incognito module in Meterpreter to impersonate BUILTIN\Administrators token for SYSTEM access.

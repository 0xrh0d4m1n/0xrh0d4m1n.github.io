---
platform: "thm"
category: "redteam"
title: "Internal"
date: 2024-08-05
difficulty: "Hard"
tags:
  - TryHackMe
  - Writeup
  - Linux
  - WordPress
  - Docker
  - SSH Tunneling
---

# **Internal**

> Mock writeup — TryHackMe Hard room simulating a penetration test against an internal WordPress server with Docker pivot.

## Reconnaissance

WordPress installation with weak admin credentials. Internal Jenkins instance accessible only through SSH tunnel.

## Exploitation

Bruteforced WordPress admin, uploaded a PHP reverse shell via theme editor. Discovered Docker credentials and Jenkins on localhost.

## Pivot & Privilege Escalation

SSH tunneled to reach Jenkins, exploited script console for container escape, and found root credentials in a mounted volume.

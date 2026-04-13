---
platform: "vulnhub"
category: "redteam"
title: "Mr. Robot"
date: 2023-08-22
difficulty: "Medium"
tags:
  - VulnHub
  - Writeup
  - Linux
  - WordPress
  - Nmap
  - SUID
---

# **Mr. Robot**

> Mock writeup — VulnHub Medium machine themed after the TV show, featuring WordPress exploitation and SUID privilege escalation.

## Reconnaissance

WordPress site with a robots.txt revealing a custom wordlist and the first key.

## Exploitation

Used the discovered wordlist to bruteforce WordPress admin. Uploaded PHP reverse shell via theme editor for initial access.

## Privilege Escalation

Found a setuid Nmap binary (interactive mode) that allowed shell escape to root.

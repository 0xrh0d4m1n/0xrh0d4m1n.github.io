---
platform: "htb"
category: "redteam"
title: "Sandworm"
date: 2023-11-18
difficulty: "Medium"
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - SSTI
  - Rust
---

# **Sandworm**

> Mock writeup — HackTheBox Medium machine involving Server-Side Template Injection in a GPG web interface.

## Reconnaissance

Web application providing GPG key verification and signature services, built with Python Flask and Rust backend.

## Exploitation

SSTI vulnerability in the GPG signature verification endpoint allowed remote code execution through crafted GPG key UIDs.

## Privilege Escalation

Exploited a Rust binary with a Firejail escape to achieve root access.

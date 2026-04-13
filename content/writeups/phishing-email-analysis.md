---
platform: "letsdefend"
category: "blueteam"
title: "Phishing Email Analysis"
date: 2024-04-18
difficulty: "Easy"
tags:
  - Blue Team
  - LetsDefend
  - Phishing
  - Email Forensics
  - SOC
---

# **Phishing Email Analysis**

> Mock writeup — LetsDefend Easy challenge analyzing a suspicious phishing email targeting corporate users.

## Scenario

SOC alert triggered by a suspicious email reported by an employee. Analyze headers, attachments, and URLs.

## Analysis

Examined email headers to trace the origin. Extracted and detonated the attached macro-enabled document in a sandbox.

## Key Findings

- Sender spoofed as internal HR department
- Return-Path and X-Originating-IP revealed external origin
- Macro document dropped a PowerShell downloader targeting known C2 infrastructure
- URL reputation check confirmed domain registered 24 hours before the attack

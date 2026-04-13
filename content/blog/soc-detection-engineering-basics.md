---
title: "SOC Detection Engineering: From Alert Fatigue to Useful Signals"
date: 2024-02-15
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://avatars.githubusercontent.com/u/106601995"
tags:
  - cybersecurity
  - SOC
  - detection-engineering
categories:
  - SOC
---

Most SOCs are not short on alerts—they are short on **useful** alerts. Detection engineering is the discipline of designing, validating, and maintaining the rules that turn raw telemetry into actionable SOC signals.

This post gives a practical, vendor-agnostic overview of how to approach detection engineering when you are working in or building a SOC.

## Start with threats, not with rules

Good detections start from a **threat model**, not from a random log field.

Some useful inputs:

- Recent incidents in your own environment.
- Public writeups (Adversary TTPs, ATT&CK techniques, CTI reports).
- Purple-team or red-team findings.

From there, you can articulate concrete **detection hypotheses**, such as:

> \"If an attacker uses RDP to pivot laterally, what traces would we expect in our logs?\"

## Telemetry first, correlation later

Before writing complex correlation rules, make sure the **raw telemetry** is:

- Ingested reliably.
- Normalized in a consistent way (hostnames, user IDs, timestamps).
- Retained for long enough to support investigations.

Many “missing detections” are actually missing or inconsistent data.

## Design detections with lifecycle in mind

Each rule should have:

- A clear **purpose** and mapped technique (e.g. ATT&CK T1021.001).
- **Test data** or replayable logs that prove it works.
- Defined **tuning knobs** (whitelists, thresholds, contextual filters).

Plan from day one how you will:

- Validate the rule in a lab.
- Deploy it in **monitor-only** mode first.
- Gradually tighten it based on feedback from analysts.

## Measure what matters

Detection engineering is continuous work. Track:

- **True positive rate** vs **false positive rate**.
- Average time from detection to triage.
- Number of incidents that were caught by each rule.

These metrics help you decide which rules deserve more engineering time and which should be retired, merged, or replaced.

When done well, detection engineering turns the SOC from a noisy alert receiver into a focused, hypothesis-driven detection program.


---
title: "Threat Hunting in the SOC: A Lightweight Playbook"
date: 2024-02-20
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://avatars.githubusercontent.com/u/106601995"
tags:
  - cybersecurity
  - SOC
  - threat-hunting
categories:
  - SOC
---

Even the best SOC detections will miss something. **Threat hunting** exists exactly for that gap: proactively looking for attackers that slipped past your alerting.

You do not need a huge team or fancy tooling to start hunting—just a bit of time, a clear question, and access to your logs.

## Step 1: Pick a narrow hypothesis

Instead of \"find all bad things\", start with something small and testable, for example:

- \"Have any endpoints executed `rundll32` with suspicious command-line arguments in the last 7 days?\"
- \"Are there interactive logons to domain controllers from unusual admin workstations?\"
- \"Did any user authenticate from two far-apart countries within one hour?\"

Write the hypothesis down. This becomes the title of your hunt.

## Step 2: Translate to data sources and queries

For each hypothesis, list:

- **Data sources** (EDR, Windows Security logs, VPN, IdP, DNS, proxy, etc.).
- The **fields** you care about (user, host, command line, IP, geo, device ID).

Then build one or more queries in your SIEM or log platform that:

- Pull the raw events.
- Aggregate or visualize them to highlight outliers.

## Step 3: Review, pivot, and tag

As you review results:

- **Mark benign patterns** (expected admin activity, known scanners).
- **Pivot** on interesting leads: same IP, same user, same parent process.
- Save intermediate queries and add notes—future you (or your teammates) will thank you.

Anything that looks truly abnormal should be promoted to an investigation or incident.

## Step 4: Turn findings into improvements

Every hunt should end with at least one of:

- A **new detection rule** or enrichment.
- A **tuning change** for an existing rule.
- A **new dashboard** or saved query to make this hunt easier next time.
- A **procedure update** in your SOC playbooks.

Threat hunting is not about catching something every single time; it is about continuously improving your visibility and understanding of how your environment behaves when it is healthy—so you quickly notice when it is not.


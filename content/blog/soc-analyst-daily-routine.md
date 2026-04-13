---
title: "Inside the SOC: A Day in the Life of a Tier 1 Analyst"
date: 2024-02-10
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://avatars.githubusercontent.com/u/106601995"
tags:
  - cybersecurity
  - SOC
  - blue-team
categories:
  - SOC
---

Working in a Security Operations Center (SOC) can look glamorous from the outside—big dashboards, fancy detections, incident bridges—but the day-to-day reality is closer to disciplined, structured routine than to constant Hollywood-style action.

In this post, we walk through a typical day in the life of a **Tier 1 SOC analyst**, focusing on the practices that keep the team operational and the signal-to-noise ratio under control.

## Starting the shift: hygiene before heroics

Most good shifts begin with hygiene tasks, not heroics:

- **Handover review**: Read the previous shift notes, ongoing incidents, and any “watch out for this” items.
- **Queue triage**: Check open alerts by severity and source (EDR, SIEM, email gateway, WAF, etc.).
- **Health checks**: Confirm that data sources, correlation rules, and dashboards are actually receiving events.

Skipping this step usually means spending the rest of the shift chasing side effects instead of root causes.

## Alert triage: deciding what deserves attention

Tier 1 analysts are the first filter between raw alerts and real incidents.

Some key principles:

- **Enrich before decide**: Always pull context (asset owner, business criticality, geolocation, threat intel hits) before closing or escalating.
- **Think in timelines**: A single alert is rarely enough; look for previous activity from the same host, user, or IP.
- **Tag as you go**: Use labels or tags for common patterns (false positive, tuning candidate, misconfiguration) so they can be revisited later.

This is where **playbooks** shine: consistent triage steps reduce mistakes and make metrics reliable.

## Escalation and incident handling

When something looks truly suspicious, Tier 1 escalates to **Tier 2 / Incident Response**. A good escalation includes:

- A short summary in plain language.
- Timeline of key events.
- Screenshots or raw logs that support the hypothesis.
- Impact estimate (what system, what data, what user).

The goal is to hand over enough context that the next analyst can jump straight into deep investigation or containment, instead of redoing triage.

## Lessons learned at the end of the shift

Healthy SOCs invest at least a little time every shift in improvement:

- Propose **rule tuning** for noisy detections.
- Document **quick wins** (queries, dashboards, or scripts that helped).
- Capture **playbook gaps**: “next time we see this pattern, we should...”

Tier 1 work is where most detections live or die. Good habits here improve everything downstream—from incident response to threat hunting and even red team exercises.


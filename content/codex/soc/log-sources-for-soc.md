---
title: "SOC Log Sources: What to Collect First"
tags: [soc, logging, seed]
---

# **SOC Log Sources: What to Collect First (Seed)**

> Seed entry for the Codex → SOC section so we can see how the theme renders topic navigation and sidebars with more content.

When building or maturing a SOC, one of the hardest practical questions is **\"which log sources should we onboard first?\"**  
This page gives a prioritized, opinionated list you can refine for your own environment.

---

## Tier 0 — Absolutely essential

- **Identity provider / AD / IdP** – logons, MFA events, password changes, group membership.
- **Endpoints (EDR)** – process creation, network connections, detections.
- **Perimeter firewall / VPN** – inbound/outbound traffic, remote access, geo anomalies.

## Tier 1 — Strongly recommended

- **Email gateway** – phishing detections, malicious attachments, URL rewrites.
- **Critical servers** – domain controllers, database servers, jump hosts.
- **Cloud control plane** – IAM changes, new keys, policy changes.

## Tier 2 — Nice to have (depending on context)

- **DNS and proxy logs** – domain lookups and web requests for threat hunting.
- **WAF / reverse proxies** – web attack patterns and blocked requests.
- **OT / ICS telemetry** – for environments with industrial systems.

Use this page as a starting point and extend it with your own environment-specific priorities and examples.


---
title: "Building an Incident Response Playbook"
date: 2024-02-28
description: "A template and guide for creating structured incident response playbooks that improve your team's efficiency during security incidents."
tags: ["incident-response", "soc", "blue-team", "dfir", "compliance"]
categories: ["Blue Team"]
image: "https://picsum.photos/seed/irplay11/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Why Playbooks Matter

An incident response (IR) playbook provides **structured, repeatable procedures** for handling security incidents. Without playbooks, teams rely on ad-hoc responses that are inconsistent and error-prone.

### The NIST IR Framework

The playbook structure follows the four NIST 800-61 phases:

1. **Preparation** -- tools, training, communication channels
2. **Detection & Analysis** -- identification and triage
3. **Containment, Eradication & Recovery** -- stopping the threat
4. **Post-Incident Activity** -- lessons learned and improvement

## Playbook Template: Ransomware Incident

### Severity Classification

| Severity | Criteria | Response Time |
|----------|----------|--------------|
| **P1 - Critical** | Active encryption, multiple systems | Immediate (< 15 min) |
| **P2 - High** | Ransomware detected, not yet executed | < 1 hour |
| **P3 - Medium** | Ransomware indicators found in logs | < 4 hours |
| **P4 - Low** | Phishing email with ransomware payload blocked | < 24 hours |

### Phase 1: Detection

Triggers for this playbook:

- EDR alert for ransomware behavior (file encryption patterns)
- User reports of inaccessible files or ransom notes
- SIEM correlation rule for mass file modification
- Threat intelligence match on known ransomware IOCs

### Phase 2: Analysis

```bash
# Identify affected systems
grep -r "encrypted\|ransom\|locked" /var/log/syslog

# Check for known ransomware file extensions
find /shared -name "*.encrypted" -o -name "*.locked" -o -name "*.crypted" 2>/dev/null

# Review recent process execution (Windows)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-4)} |
  Select-Object TimeCreated, @{n='Process';e={$_.Properties[5].Value}}
```

### Phase 3: Containment

**Immediate actions** (in order):

1. Isolate affected endpoints from the network
2. Disable compromised accounts
3. Block known C2 domains and IPs at the firewall
4. Preserve forensic evidence before remediation
5. Notify incident commander and escalation contacts

> **Do not pay the ransom** without consulting legal counsel and executive leadership. Payment does not guarantee data recovery and may fund further criminal activity.

### Phase 4: Recovery

- Restore from *verified clean backups*
- Rebuild compromised systems from known-good images
- Reset all credentials for affected accounts
- Monitor recovered systems for signs of re-infection
- Validate data integrity after restoration

### Phase 5: Post-Incident

**Lessons learned meeting** should cover:

- Timeline of events from detection to resolution
- What worked well and what needs improvement
- Gaps in detection, tooling, or processes
- Action items with assigned owners and deadlines

```yaml
# Post-incident report metadata
incident_id: "IR-2024-0042"
severity: "P1"
category: "Ransomware"
detection_time: "2024-02-28T08:15:00Z"
containment_time: "2024-02-28T08:45:00Z"
resolution_time: "2024-02-28T18:30:00Z"
total_duration: "10h 15m"
affected_systems: 23
data_loss: "None (restored from backup)"
root_cause: "Phishing email with macro-enabled document"
```

Build playbooks for your most common incident types and **rehearse them regularly** through tabletop exercises. A playbook is only useful if the team knows how to follow it.

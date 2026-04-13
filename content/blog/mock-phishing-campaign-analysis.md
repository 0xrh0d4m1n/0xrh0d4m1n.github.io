---
title: "Analyzing Phishing Campaigns: A SOC Analyst's Guide"
date: 2026-03-05
description: "Step-by-step methodology for analyzing phishing emails, extracting IOCs, and building detection rules to protect your organization."
tags: ["phishing", "soc", "blue-team", "incident-response", "email-security"]
categories: ["SOC"]
image: "https://picsum.photos/seed/phish15/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Phishing Remains the Top Vector

Phishing continues to be the **most successful initial access technique** used by attackers. Understanding how to quickly analyze and respond to phishing campaigns is a core SOC skill.

## Email Header Analysis

Every investigation starts with examining the email headers:

```bash
# Key headers to examine
# 1. Return-Path - actual sender
# 2. Received - mail server chain
# 3. X-Originating-IP - sender's IP
# 4. Authentication-Results - SPF/DKIM/DMARC

# Extract headers from .eml file
cat phishing.eml | grep -E "^(From|To|Subject|Return-Path|Received|X-Originating|Authentication)"
```

### Authentication Check Results

| Check | Pass | Fail Indicator |
|-------|------|----------------|
| **SPF** | Sender IP is authorized | Spoofed sender domain |
| **DKIM** | Signature verified | Tampered content |
| **DMARC** | SPF+DKIM aligned | No domain policy enforcement |

## URL and Attachment Analysis

### Safe URL Inspection

1. **Never click** links directly -- use analysis tools
2. Hover to reveal the actual URL vs. displayed text
3. Check for lookalike domains (homograph attacks)
4. Submit to sandbox environments

```bash
# Expand shortened URLs safely
curl -sI "https://bit.ly/suspicious" | grep -i "location"

# Check URL reputation
curl -s "https://www.virustotal.com/api/v3/urls" \
  -H "x-apikey: YOUR_KEY" \
  -d "url=https://suspicious-domain.com"

# Whois lookup on the domain
whois suspicious-domain.com | grep -E "Creation|Registrar|Name Server"
```

### Attachment Analysis

```bash
# Get file hash without opening
sha256sum suspicious_attachment.docx

# Check hash on VirusTotal
vt file <hash>

# Extract macros from Office documents
olevba suspicious_attachment.docx

# Analyze in a sandbox
# Submit to Any.Run, Joe Sandbox, or Hybrid Analysis
```

## Common Phishing Indicators

Watch for these red flags in reported emails:

- **Urgency language** -- *"Your account will be suspended"*
- **Mismatched URLs** -- display text differs from actual href
- **Lookalike domains** -- `micros0ft.com`, `paypa1.com`
- **Generic greetings** -- "Dear Customer" instead of using your name
- **Suspicious attachments** -- `.html`, `.iso`, `.img`, password-protected `.zip`
- **Reply-to mismatch** -- From and Reply-To are different addresses

## Building Detection Rules

```yaml
# Example email gateway rule
rule_name: "Phishing - Credential Harvesting Redirect"
conditions:
  - header.from.domain NOT IN corporate_domains
  - body.url.domain.age < 30 days
  - body.url.path CONTAINS "/login" OR "/signin" OR "/verify"
  - body.text MATCHES "urgent|verify|suspend|expire"
actions:
  - quarantine
  - notify_soc
  - add_tag: "phishing-suspect"
```

## Response Checklist

When a phishing email is confirmed:

- [ ] Block sender domain and IP at the email gateway
- [ ] Search mailboxes for other recipients of the same campaign
- [ ] Remove the email from all affected inboxes
- [ ] Check if any user clicked the link or opened the attachment
- [ ] Reset credentials for any users who submitted data
- [ ] Update detection rules with new IOCs
- [ ] Notify affected users with guidance

> Speed matters in phishing response. The faster you can identify all recipients and remove the emails, the lower the chance of a successful compromise.

Build a **phishing response playbook** and practice it regularly. Automated tools like PhishER or Cofense can significantly reduce response times.

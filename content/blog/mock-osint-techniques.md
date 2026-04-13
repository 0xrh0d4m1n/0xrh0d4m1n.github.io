---
title: "OSINT Reconnaissance Techniques for Security Professionals"
date: 2025-09-03
description: "Explore open-source intelligence gathering techniques used in security assessments, threat investigations, and digital forensics."
tags: ["osint", "red-team", "reconnaissance", "tools", "threat-intelligence"]
categories: ["Red Team"]
image: "https://picsum.photos/seed/osint8/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## What is OSINT?

Open-Source Intelligence (OSINT) is the collection and analysis of information from **publicly available sources**. In cybersecurity, OSINT is used for both *offensive reconnaissance* and *defensive threat intelligence*.

## Domain and Infrastructure Recon

### DNS Enumeration

```bash
# Subdomain enumeration with subfinder
subfinder -d example.com -o subdomains.txt

# DNS record lookup
dig example.com ANY +noall +answer
dig example.com MX +short

# Reverse DNS lookup
host 93.184.216.34

# Zone transfer attempt
dig @ns1.example.com example.com AXFR
```

### WHOIS and Certificate Transparency

```bash
# WHOIS information
whois example.com

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq -r '.[].name_value' | sort -u

# Historical DNS records via SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
  -H "APIKEY: YOUR_API_KEY"
```

## People and Organization OSINT

Key sources for gathering intelligence on people and organizations:

- **LinkedIn** -- employee roles, technologies used, organizational structure
- **GitHub** -- code repositories, API keys in commits, technology stack
- **Job Postings** -- reveal internal tools, platforms, and security gaps
- **Social Media** -- geolocation data, personal details, insider information
- **Public Records** -- corporate filings, domain registrations, patents

> The most dangerous data leaks often come from employees unknowingly sharing sensitive details on public platforms.

## Useful OSINT Tools

| Tool | Purpose | Type |
|------|---------|------|
| Maltego | Relationship mapping | GUI |
| theHarvester | Email/subdomain collection | CLI |
| Shodan | Internet-connected device search | Web/API |
| Recon-ng | Modular OSINT framework | CLI |
| SpiderFoot | Automated OSINT collection | Web/CLI |
| Sherlock | Username search across platforms | CLI |

### Quick theHarvester Example

```bash
# Gather emails and subdomains
theHarvester -d example.com -b google,bing,linkedin -l 500

# Export results to XML
theHarvester -d example.com -b all -f results.xml
```

## Google Dorking

Crafting precise search queries to find exposed information:

1. `site:example.com filetype:pdf` -- find PDF documents
2. `site:example.com inurl:admin` -- locate admin panels
3. `"example.com" password filetype:log` -- search for leaked credentials
4. `intitle:"index of" site:example.com` -- find directory listings
5. `site:pastebin.com "example.com"` -- check paste sites for leaks

## Building an OSINT Workflow

- **Define objectives** clearly before starting collection
- **Document everything** with timestamps and source URLs
- Use *multiple sources* to corroborate findings
- Respect **legal boundaries** and platform terms of service
- Store findings in a structured format for analysis

OSINT is a powerful first step in any security assessment. The information gathered shapes the entire engagement strategy.

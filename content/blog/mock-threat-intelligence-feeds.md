---
title: "Setting Up Threat Intelligence Feeds"
date: 2025-05-12
description: "A practical guide to integrating open-source and commercial threat intelligence feeds into your security operations workflow."
tags: ["threat-intelligence", "soc", "blue-team", "osint", "automation"]
categories: ["Tools"]
image: "https://picsum.photos/seed/tifeeds20/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Threat Intelligence in the SOC

Threat intelligence (TI) feeds provide **actionable indicators of compromise** (IOCs) and contextual information that helps SOC teams detect, prioritize, and respond to threats more effectively.

## Types of Intelligence

| Type | Description | Example |
|------|-------------|---------|
| **Strategic** | High-level trends, motivations | APT targeting your sector |
| **Tactical** | TTPs used by adversaries | Spear-phishing with ISO files |
| **Operational** | Campaign details, IOCs | Specific C2 domains and IPs |
| **Technical** | Machine-readable indicators | IP addresses, hashes, URLs |

## Open-Source Feed Setup

### MISP Integration

```bash
# Install MISP (using Docker for simplicity)
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env

# Edit .env with your configuration
# Then start the stack
docker compose up -d

# Verify MISP is running
curl -k https://localhost:443/users/login
```

### Configuring Feed Sources

```python
# Python script to pull and parse an OSINT feed
import requests
import json
from datetime import datetime

FEEDS = {
    "abuse_ch_urlhaus": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "abuse_ch_feodotracker": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "emergingthreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
}

def fetch_ip_blocklist(url: str) -> list:
    """Fetch and parse an IP blocklist feed."""
    response = requests.get(url, timeout=30)
    ips = []
    for line in response.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.append(line)
    return ips

def enrich_ioc(ioc: str, ioc_type: str = "ip") -> dict:
    """Enrich an IOC with additional context."""
    return {
        "indicator": ioc,
        "type": ioc_type,
        "source": "abuse_ch",
        "first_seen": datetime.utcnow().isoformat(),
        "confidence": 75,
        "tags": ["malware", "c2"]
    }

if __name__ == "__main__":
    ips = fetch_ip_blocklist(FEEDS["abuse_ch_feodotracker"])
    print(f"[+] Fetched {len(ips)} malicious IPs")
    enriched = [enrich_ioc(ip) for ip in ips[:5]]
    print(json.dumps(enriched, indent=2))
```

## Recommended Open-Source Feeds

1. **AlienVault OTX** -- community-driven threat data with pulse system
2. **Abuse.ch** -- URLhaus, Feodo Tracker, MalwareBazaar, ThreatFox
3. **CIRCL OSINT** -- MISP-compatible feeds from CIRCL Luxembourg
4. **PhishTank** -- community-verified phishing URLs
5. **Emerging Threats** -- Suricata/Snort rulesets and IP blocklists
6. **VirusTotal** -- file and URL scanning with community detection

## STIX/TAXII Integration

The standard format for sharing threat intelligence:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
  "created": "2025-05-12T10:00:00Z",
  "modified": "2025-05-12T10:00:00Z",
  "name": "Malicious C2 Domain",
  "pattern": "[domain-name:value = 'evil-c2-server.xyz']",
  "pattern_type": "stix",
  "valid_from": "2025-05-12T10:00:00Z",
  "labels": ["malicious-activity"],
  "confidence": 85
}
```

### Connecting to a TAXII Server

```bash
# Using cabby (TAXII client)
pip install cabby

# Discover available collections
taxii-discovery --host taxii.example.com --port 443 --https

# Poll for indicators
taxii-poll --host taxii.example.com --collection "threat-data" \
  --begin 2025-05-01 --end 2025-05-12
```

## Feed Quality Assessment

Not all feeds are equal. Evaluate feeds based on:

- **Timeliness** -- how quickly are new indicators published?
- **Accuracy** -- what is the false positive rate?
- **Context** -- are indicators enriched with TTPs and attribution?
- **Coverage** -- does the feed align with your threat landscape?
- **Format** -- is it machine-readable (STIX, CSV, JSON)?

> Quantity of indicators does not equal quality. A feed with *100 high-confidence IOCs* is more valuable than one with 10,000 unverified entries.

Start with a few high-quality feeds and expand as your team matures its intelligence processing capabilities. Automate ingestion and integrate directly with your SIEM and EDR platforms for maximum operational value.

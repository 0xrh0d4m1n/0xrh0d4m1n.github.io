---
title: "Web Application Testing with Burp Suite"
date: 2024-05-08
description: "A practical walkthrough of using Burp Suite Professional for web application penetration testing, from setup to exploitation."
tags: ["web-security", "red-team", "burp-suite", "pentesting", "tools"]
categories: ["Red Team"]
image: "https://picsum.photos/seed/burp7/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Getting Started with Burp Suite

Burp Suite is the **de facto standard** for web application security testing. Whether you are performing bug bounties or enterprise pentests, understanding its core modules is critical.

### Initial Configuration

1. Download and install Burp Suite from PortSwigger
2. Configure your browser to use `127.0.0.1:8080` as the proxy
3. Install Burp's CA certificate for HTTPS interception
4. Set your target scope to avoid testing out-of-scope assets

### Browser Proxy Setup

```bash
# Using FoxyProxy or manual browser settings
# HTTP Proxy: 127.0.0.1
# Port: 8080

# For CLI tools, export the proxy variable
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

## Core Modules

| Module | Purpose | Key Feature |
|--------|---------|-------------|
| **Proxy** | Intercept/modify traffic | Request/response manipulation |
| **Scanner** | Automated vulnerability detection | Active and passive scanning |
| **Repeater** | Manual request testing | Quick parameter fuzzing |
| **Intruder** | Automated attacks | Payload position marking |
| **Decoder** | Encode/decode data | Base64, URL, HTML encoding |
| **Comparer** | Diff responses | Side-by-side comparison |

## Testing Authentication Bypass

A common test involves manipulating session tokens. Here is an example of testing JWT manipulation:

```python
import jwt
import base64
import json

# Decode without verification to inspect claims
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
header = json.loads(base64.b64decode(token.split('.')[0] + '=='))
payload = json.loads(base64.b64decode(token.split('.')[1] + '=='))

print(f"Algorithm: {header['alg']}")
print(f"User Role: {payload.get('role', 'N/A')}")

# Test 'none' algorithm bypass
modified_header = base64.b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).decode().rstrip('=')

payload['role'] = 'admin'
modified_payload = base64.b64encode(
    json.dumps(payload).encode()
).decode().rstrip('=')

forged_token = f"{modified_header}.{modified_payload}."
print(f"Forged: {forged_token}")
```

## Intruder Attack Types

- **Sniper** -- single payload position, one list, iterate through each position
- **Battering Ram** -- same payload in all positions simultaneously
- **Pitchfork** -- multiple payload sets, one per position, parallel iteration
- **Cluster Bomb** -- multiple payload sets, all combinations tested

### Useful Extensions

> The **BApp Store** contains hundreds of community extensions. Start with these essentials.

- `Logger++` -- advanced HTTP logging and filtering
- `Autorize` -- automated authorization testing
- `Param Miner` -- hidden parameter discovery
- `JSON Web Tokens` -- JWT analysis and manipulation
- `Active Scan++` -- enhanced scanning checks

## Reporting Tips

After testing, generate a report that includes:

1. Executive summary with *risk ratings*
2. Technical findings with **proof-of-concept** screenshots
3. Remediation recommendations ordered by severity
4. Re-test verification steps

Always practice **responsible disclosure** and obtain written authorization before testing any web application.

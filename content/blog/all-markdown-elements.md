---
title: "All Markdown Elements"
date: 2026-04-12
description: "A comprehensive reference post testing every Markdown and MDX element to verify how they render on the site. Use this as a visual QA checklist."
tags: ["markdown", "showcase", "testing", "reference"]
categories: ["Markdown"]
image: "https://picsum.photos/seed/mdx-reference/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Headings

The following heading levels are available in Markdown:

# Heading Level 1

## Heading Level 2

### Heading Level 3

#### Heading Level 4

##### Heading Level 5

###### Heading Level 6

---

## Paragraphs and Inline Formatting

This is a regular paragraph. It contains **bold text**, *italic text*, ***bold and italic***, ~~strikethrough~~, and `inline code`. You can also use [internal links](/about/) and [external links](https://owasp.org/).

Here's a second paragraph to test spacing between blocks. Line breaks can be forced
with two trailing spaces (like above) or with a `<br/>` tag.

---

## Blockquotes

> This is a simple blockquote. It can contain **bold**, *italic*, and `inline code`.

> Multi-paragraph blockquote.
>
> This is the second paragraph inside the same quote block. Notice the spacing.

> Nested blockquote:
>
> > This is a nested blockquote inside the outer one.
> > It can also span multiple lines.

> **Tip:** Blockquotes are great for highlighting important information, warnings, or tips for the reader.

---

## Unordered Lists

- First item in the list
- Second item with **bold text** and `inline code`
- Third item
  - Nested item one
  - Nested item two
    - Deep nested item
- Fourth item

---

## Ordered Lists

1. First step
2. Second step with **bold** and a [link](https://example.com)
3. Third step
   1. Sub-step A
   2. Sub-step B
      1. Sub-sub-step
4. Fourth step

---

## Mixed Lists

1. **Reconnaissance phase**
   - Subdomain enumeration
   - Port scanning
   - Technology fingerprinting
2. **Exploitation phase**
   - Vulnerability validation
   - Payload development
3. **Post-exploitation**
   - Persistence
   - Lateral movement
   - Data exfiltration

---

## Task Lists (GFM)

- [x] Initial reconnaissance completed
- [x] Vulnerability assessment done
- [ ] Exploitation phase
- [ ] Post-exploitation report
- [ ] Final report delivery

---

## Code Blocks

### Bash / Shell

```bash
#!/bin/bash
# Quick port scan
echo "[*] Scanning target..."
nmap -sV -sC -oA scan_results 10.10.10.1
grep -r "password" /var/log/ 2>/dev/null
echo "[+] Scan complete"
```

### Python

```python
import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(host: str, port: int) -> dict:
    """Check if a port is open on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return {"port": port, "status": "open" if result == 0 else "closed"}
    except socket.error:
        return {"port": port, "status": "error"}

if __name__ == "__main__":
    target = "10.10.10.1"
    ports = range(1, 1025)

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)

    for r in results:
        if r["status"] == "open":
            print(f"[+] Port {r['port']} is OPEN")
```

### JavaScript / TypeScript

```typescript
interface ScanResult {
  port: number;
  status: "open" | "closed" | "filtered";
  service?: string;
}

async function scanTarget(host: string, ports: number[]): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  for (const port of ports) {
    const status = await checkPort(host, port);
    results.push({ port, status });
  }
  return results.filter((r) => r.status === "open");
}
```

### JSON

```json
{
  "alert": {
    "id": "ALT-2026-0412",
    "severity": "critical",
    "source": "SIEM",
    "tags": ["malware", "c2", "lateral-movement"],
    "indicators": {
      "ip": "198.51.100.42",
      "domain": "evil.example.com",
      "hash": "e99a18c428cb38d5f260853678922e03"
    }
  }
}
```

### YAML

```yaml
playbook:
  name: "Phishing Response"
  severity: high
  steps:
    - name: Extract IOCs
      action: parse_email_headers
      timeout: 30s
    - name: Check reputation
      action: query_virustotal
      api_key: ${VT_API_KEY}
    - name: Block sender
      action: update_email_filter
      condition: reputation_score > 7
```

### SQL

```sql
-- Find failed login attempts in the last 24 hours
SELECT
    username,
    source_ip,
    COUNT(*) AS attempt_count,
    MIN(timestamp) AS first_attempt,
    MAX(timestamp) AS last_attempt
FROM auth_logs
WHERE event_type = 'LOGIN_FAILED'
  AND timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY username, source_ip
HAVING COUNT(*) > 5
ORDER BY attempt_count DESC;
```

### Plain Text (no syntax highlighting)

```
[2026-04-12 08:15:23] INFO  - Service started on port 8080
[2026-04-12 08:15:24] WARN  - TLS certificate expires in 7 days
[2026-04-12 08:15:30] ERROR - Connection refused: 10.10.10.5:443
[2026-04-12 08:15:31] INFO  - Retry attempt 1/3...
```

### Diff

```diff
- old_firewall_rule = "ALLOW ALL"
+ new_firewall_rule = "DENY ALL; ALLOW 10.0.0.0/8"

- logging_level = "INFO"
+ logging_level = "DEBUG"
```

---

## Tables

### Simple Table

| Tool | Category | Use Case |
|------|----------|----------|
| Nmap | Recon | Port scanning and service detection |
| Burp Suite | Web Security | HTTP proxy and vulnerability scanning |
| Wireshark | Network | Packet capture and protocol analysis |
| Metasploit | Exploitation | Exploit development and delivery |
| Volatility | Forensics | Memory dump analysis |

### Aligned Table

| Left Aligned | Center Aligned | Right Aligned |
|:-------------|:--------------:|--------------:|
| Row 1 Col 1 | Row 1 Col 2 | Row 1 Col 3 |
| Row 2 Col 1 | Row 2 Col 2 | Row 2 Col 3 |
| Row 3 Col 1 | Row 3 Col 2 | Row 3 Col 3 |

### Table with Formatted Content

| Severity | Count | Example CVE | Status |
|----------|------:|-------------|--------|
| **Critical** | 3 | `CVE-2021-44228` | Patched |
| **High** | 12 | `CVE-2023-20198` | In Progress |
| **Medium** | 28 | `CVE-2024-1234` | *Pending* |
| **Low** | 45 | `CVE-2024-5678` | Accepted |

### Wide Table (overflow test)

| Timestamp | Source IP | Destination IP | Source Port | Dest Port | Protocol | Action | Rule ID | Category | Severity | Message |
|-----------|-----------|----------------|-------------|-----------|----------|--------|---------|----------|----------|---------|
| 2026-04-12T08:15:23Z | 192.168.1.100 | 10.10.10.5 | 54321 | 443 | TCP | ALLOW | FW-001 | Web Traffic | Low | HTTPS connection established |
| 2026-04-12T08:15:24Z | 198.51.100.42 | 192.168.1.50 | 80 | 8080 | TCP | BLOCK | IDS-042 | C2 Communication | Critical | Known C2 domain detected |

---

## Links

- [Internal link to About page](/about/)
- [External link to OWASP](https://owasp.org/)
- [Link with title](https://example.com "Hover to see this title")
- Autolinked URL: https://github.com/0xrh0d4m1n

---

## Images

### Regular Image

![Cybersecurity Lab Setup](https://res.cloudinary.com/a88188f90768a608fc75048188ef19e7/image/upload/q_auto/f_auto/v1776380568/Website/About/b0740b2a8afc9453749b5e013a2db6fb_lp1jkn.png)

### External Image

![Random Placeholder](https://picsum.photos/seed/markdown-test/600/300)

---

## Horizontal Rules

Three different syntaxes produce the same result:

---

***

___

---

## HTML Elements in MDX

### Details / Summary (Collapsible)

<details>
<summary>Click to expand — MITRE ATT&CK Techniques</summary>

- **T1566** — Phishing
- **T1059** — Command and Scripting Interpreter
- **T1078** — Valid Accounts
- **T1071** — Application Layer Protocol

These are commonly seen in APT campaigns targeting enterprise networks.

</details>

<details>
<summary>Click to expand — Incident Response Checklist</summary>

1. **Identification** — Detect and confirm the incident
2. **Containment** — Isolate affected systems
3. **Eradication** — Remove the threat
4. **Recovery** — Restore systems to normal
5. **Lessons Learned** — Document and improve

</details>

---

## Footnotes

Here is a sentence with a footnote reference[^1] and another one[^2].

[^1]: This is the first footnote content.
[^2]: This is the second footnote with **bold** and `code`.

---

## Abbreviations and Special Characters

Special characters: &copy; 2026 &mdash; &ndash; &hellip; &rarr; &larr; &uarr; &darr;

Emojis (if supported): :lock: :shield: :warning:

Mathematical-like: 2<sup>10</sup> = 1024, H<sub>2</sub>O, CO<sub>2</sub>

---

## Escaping and Edge Cases

- Backslash escapes: \* \# \` \[ \] \{ \}
- Code with special chars: `$PATH`, `<script>alert('xss')</script>`
- Backticks in code: `` `nested backtick` ``
- HTML entities: `&amp;` renders as &amp;, `&lt;` renders as &lt;

---

## Long Paragraph (Line Wrapping)

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Curabitur pretium tincidunt lacus nulla gravida orci a odio tonka non commodo luctus nisi erat porttitor ligula euismod egestas lacinia a felis.

---

## Summary

This reference post includes every Markdown element: **headings** (h2-h6), **paragraphs**, **inline formatting** (bold, italic, strikethrough, code), **blockquotes** (single, multi-paragraph, nested), **unordered lists**, **ordered lists**, **mixed lists**, **task lists**, **code blocks** (bash, python, typescript, json, yaml, sql, plain text, diff), **tables** (simple, aligned, formatted, wide), **links** (internal, external, titled, auto), **images**, **horizontal rules**, **HTML details/summary**, **footnotes**, **special characters**, and **escaping**. Use it as a visual QA checklist.

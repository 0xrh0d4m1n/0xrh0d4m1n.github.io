---
platform: "cyberdefenders"
category: "blueteam"
title: "Markdown Showcase Lab — Dummy Writeup for Rendering Tests"
date: 2025-03-15
difficulty: "Medium"
tags:
  - showcase
  - blue-team
  - cyberdefenders
categories:
  - blueteam
---

This is a **dummy writeup** to test Markdown rendering in the writeups section. It includes the same variety of elements as the blog showcase.

[← Back to CyberDefenders](/writeups/blueteam/cyberdefenders/)

---

# Markdown Showcase Lab

## Overview

*Dummy* lab to verify **headings**, lists, code, tables, and blockquotes in writeup pages.

### Objectives

- [x] Test heading hierarchy (h1–h6)
- [x] Test **bold**, *italic*, `code`
- [ ] Test images and links
- [ ] Test code blocks and tables

---

## Reconnaissance

We start with a typical recon workflow.

### 1. Subdomains

```bash
subfinder -d target.com -o subs.txt
amass enum -d target.com
```

### 2. Port scan

| Port | Service | Notes     |
| ---- | ------- | --------- |
| 22   | SSH     | Open      |
| 80   | HTTP    | Web server |
| 443  | HTTPS   | TLS       |

### 3. Web tech

- **Server**: Apache/2.4
- **Framework**: PHP
- **Headers**: `X-Powered-By: PHP/8.1`

---

## Blockquotes and lists

> Important note: This is a **blockquote** inside a writeup. Use it for tips or key findings.

Ordered steps:

1. **Step one** — run `nmap`.
2. **Step two** — enumerate web paths.
3. **Step three** — analyze results.

Unordered items:

- Item with **bold**
- Item with `inline code`
- Nested
  - Sub-item A
  - Sub-item B

---

## Code blocks (multiple languages)

**Python snippet:**

```python
import requests
r = requests.get("http://target/")
print(r.status_code)
```

**JSON response:**

```json
{"user": "admin", "role": "superuser"}
```

**Shell one-liner:**

```sh
curl -s http://target/ | grep -oP 'href="[^"]*"'
```

---

## Tables (alignment and content)

| Tool        | Type   | Purpose        |
| ----------- | ------ | -------------- |
| Wireshark   | Network| Packet capture |
| Volatility  | Memory | Forensic analysis |
| Autopsy     | Disk   | Disk imaging   |

| Left | Center | Right |
| :--- | :----: | ---: |
| A    | B      | C    |

---

## Horizontal rules and sections

Section one content.

---

Section two content.

***

Section three with `code` and **bold**.

---

## HTML: details/summary

<details>
<summary>Expand for extra notes</summary>

Internal content with **formatting** and a [link](/blog/). Code: `nmap -sV target`.
</details>

---

## Long paragraph (wrapping test)

This paragraph is intentionally long to see how the writeup layout handles wrapping. In a real scenario you would describe the vulnerability, the steps to reproduce, and the impact. For now we only need to ensure that multiple lines of text wrap correctly and that the reading experience is comfortable. No line breaks inside this paragraph except the natural flow of the container.

---

## Conclusion

This dummy writeup demonstrated:

- **Headings** (h1–h6)
- **Text** — bold, italic, code
- **Lists** — ordered, unordered, task lists
- **Blockquotes**
- **Code blocks** — bash, python, json, sh
- **Tables** — with and without alignment
- **Horizontal rules**
- **HTML** `<details>` / `<summary>`
- **Links** — internal and external

Use it to verify writeup page styling and MDX rendering.

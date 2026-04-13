---
title: "Markdown Elements Showcase — Testing All Possible Syntax"
date: 2025-03-15
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://avatars.githubusercontent.com/u/106601995"
tags:
  - showcase
  - markdown
  - testing
categories:
  - cybersecurity
---

This is a **dummy blog post** designed to test how every Markdown element renders on the site. Use it to verify headings, lists, code blocks, tables, blockquotes, and more.

---

# Heading level 1 — Main title

Paragraph with **bold**, *italic*, and `inline code`. We can also use ~~strikethrough~~ and **_bold italic_**. Links: [internal](/about/) and [external](https://example.com).  
Same paragraph, second sentence. Line break above was two spaces + newline.

## Heading level 2 — Sections

A normal paragraph. **Bold phrase** and *italic phrase* and `` `code` ``. Escaping: \*not italic\* and \`not code\`.

### Heading level 3 — Subsections

Text with **nested *formatting*** and `code with **ignored** markdown`.

#### Heading level 4

Short paragraph under h4.

##### Heading level 5

Even smaller heading.

###### Heading level 6 — Smallest

Minimum heading level.

---

## Unordered lists

- First item
- Second item
- Third item with **bold** and `code`
- Fourth item
  - Nested item one
  - Nested item two
    - Deep nested

Another list with different marker:

* Asterisk item one
* Asterisk item two

+ Plus item one
+ Plus item two

---

## Ordered lists

1. First step
2. Second step
3. Third step
   1. Sub-step A
   2. Sub-step B
4. Fourth step

---

## Blockquotes

> Single-level blockquote. **Bold** and *italic* and `code` work here too.

> Multi-paragraph blockquote.
>
> This is the second paragraph inside the same blockquote.

> Nested blockquote:
> > Level two blockquote.
> > Another line at level two.

---

## Code blocks (fenced)

Inline `code` in sentence.

**Bash / shell:**

```bash
#!/bin/bash
nmap -sV -sC 10.10.10.1
grep -r "password" /var/log/
```

**JSON:**

```json
{
  "title": "Alert",
  "severity": "high",
  "tags": ["malware", "c2"]
}
```

**Python:**

```python
def check_port(host: str, port: int) -> bool:
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0
```

**SQL:**

```sql
SELECT * FROM users WHERE role = 'admin';
-- comment
```

**Plain text (no language):**

```
Raw output or log snippet
  indented line
another line
```

---

## Tables

| Tool       | Category   | Use case        |
| ---------- | ---------- | ---------------- |
| Nmap       | Recon      | Port scanning    |
| Burp Suite | Web        | Proxy / testing  |
| Wireshark  | Network    | Packet analysis  |

| Left align | Center align | Right align |
| :--------- | :----------: | ----------: |
| left       | center       | right       |

Table with **bold** and `code` in cells:

| Syntax    | Renders as   |
| --------- | ------------ |
| **bold**  | **bold**     |
| `code`    | `code`       |

---

## Horizontal rules

Below are three different horizontal rule syntaxes:

---

***

___

---

## Task lists (GFM)

- [ ] Unchecked task one
- [ ] Unchecked task two
- [x] Checked task one
- [x] Checked task two
- [ ] Task with **bold** and `code`

---

## Links and images

- [Internal link to About](/about/)
- [External link](https://owasp.org/)
- [Link with title](https://example.com "Example title on hover")

Image (if file exists under public):

![Placeholder alt text](/img/hero/b0740b2a8afc9453749b5e013a2db6fb.png)

---

## HTML elements (supported in MDX)

<details>
<summary>Click to expand — Details / Summary</summary>

Content inside **details**. Markdown works here: *italic*, `code`, and [links](/blog/).
</details>

---

## Mixed content block

Below: a heading, a short paragraph, a list, and a code block together.

### Recon checklist

1. **Subdomain enumeration** — use tools like `subfinder`, `amass`.
2. **Port scan** — `nmap -sC -sV target`.
3. **Screenshots** — `gowitness` or similar.

```bash
nmap -sV -sC -oA scan 10.10.10.1
```

---

## Long paragraph (wrapping)

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. This paragraph tests how long blocks of text wrap and display in the prose container.

---

## Escaping and special characters

- Backslash: \* \# \` \[ \]
- In code: `$env:PATH` and `export VAR=value`
- Angle brackets in code: `<div>`, `<script>`

---

## Summary

This showcase includes: **headings** (h1–h6), **paragraphs**, **bold**, *italic*, ~~strikethrough~~, `inline code`, [links](/), images, unordered and ordered lists (including nested), blockquotes (single and nested), fenced code blocks (multiple languages), tables, horizontal rules, task lists, and HTML `<details>`/`<summary>`. Use it to verify rendering across the site.

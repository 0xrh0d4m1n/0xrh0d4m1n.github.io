---
platform: "portswigger"
category: "web"
title: "Reflected XSS into HTML context"
date: 2024-03-25
difficulty: "Easy"
tags:
  - Web
  - PortSwigger
  - XSS
  - Reflected XSS
---

# **Reflected XSS into HTML context**

> Mock writeup — PortSwigger Web Security Academy lab on reflected cross-site scripting.

## Lab Description

The search functionality has a reflected XSS vulnerability. Inject a script that calls `alert()`.

## Solution

The search parameter was reflected directly into the HTML response without sanitization:

```
https://target.web-security-academy.net/?search=<script>alert(1)</script>
```

## Key Takeaways

- Always encode user input before reflecting it in HTML context
- Content-Security-Policy headers can mitigate XSS impact

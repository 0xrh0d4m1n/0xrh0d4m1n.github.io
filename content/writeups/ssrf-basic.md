---
platform: "portswigger"
category: "web"
title: "Basic SSRF against localhost"
date: 2024-05-08
difficulty: "Easy"
tags:
  - Web
  - PortSwigger
  - SSRF
  - Server-Side
---

# **Basic SSRF against localhost**

> Mock writeup — PortSwigger Web Security Academy lab on basic Server-Side Request Forgery.

## Lab Description

The stock check feature fetches data from an internal URL. Exploit it to access the admin panel on localhost.

## Solution

Changed the stock check URL parameter to target the internal admin interface:

```
stockApi=http://localhost/admin/delete?username=carlos
```

## Key Takeaways

- Never trust user-supplied URLs for server-side requests
- Allowlist internal resources; block requests to localhost, 127.0.0.1, and metadata endpoints

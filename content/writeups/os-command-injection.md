---
platform: "portswigger"
category: "web"
title: "OS Command Injection"
date: 2024-09-01
difficulty: "Easy"
tags:
  - Web
  - PortSwigger
  - Command Injection
  - OS Injection
---

# **OS Command Injection**

> Mock writeup — PortSwigger Web Security Academy lab on simple OS command injection.

## Lab Description

The product stock checker executes a shell command with user-supplied input. Inject an arbitrary command to retrieve the contents of `/etc/passwd`.

## Solution

The `productId` and `storeId` parameters were passed directly to a shell command. Injected a pipe operator:

```
productId=1&storeId=1|cat+/etc/passwd
```

## Key Takeaways

- Never pass user input directly to shell commands
- Use language-specific APIs instead of shell execution
- Implement strict input validation with allowlists

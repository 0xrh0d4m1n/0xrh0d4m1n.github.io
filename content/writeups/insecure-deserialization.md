---
platform: "portswigger"
category: "web"
title: "Insecure Deserialization — PHP Object Injection"
date: 2024-10-18
difficulty: "Hard"
tags:
  - Web
  - PortSwigger
  - Deserialization
  - PHP
  - RCE
---

# **Insecure Deserialization — PHP Object Injection**

> Mock writeup — PortSwigger Web Security Academy lab exploiting PHP insecure deserialization to achieve remote code execution.

## Lab Description

The session cookie contains a serialized PHP object. Craft a malicious serialized object that exploits a gadget chain to execute arbitrary commands.

## Solution

1. Decoded the session cookie (base64 → PHP serialized object)
2. Identified a `CustomTemplate` class with a `__destruct()` method that called `unlink()` on a property
3. Crafted a serialized object with `lock_file_path` set to Carlos's home directory
4. For RCE: chained multiple gadgets to invoke `exec()` through the `__wakeup()` → `__toString()` chain

## Key Takeaways

- Never deserialize untrusted data
- Use JSON or other safe serialization formats for session data
- Implement integrity checks (HMAC) on serialized data if deserialization is unavoidable

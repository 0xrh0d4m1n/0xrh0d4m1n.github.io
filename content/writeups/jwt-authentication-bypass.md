---
platform: "portswigger"
category: "web"
title: "JWT Authentication Bypass via jku Header"
date: 2024-07-12
difficulty: "Medium"
tags:
  - Web
  - PortSwigger
  - JWT
  - Authentication
---

# **JWT Authentication Bypass via jku Header**

> Mock writeup — PortSwigger Web Security Academy lab exploiting JWT jku header injection.

## Lab Description

The server uses JWTs with a jku (JWK Set URL) header to verify signatures. Exploit the jku header to forge a valid admin JWT.

## Solution

1. Generated a custom RSA key pair
2. Hosted the public key on the exploit server as a JWK Set
3. Modified the JWT claims to `"sub": "administrator"` and set `jku` to our server
4. Signed the token with our private key

## Key Takeaways

- Servers must validate the `jku` URL against a strict allowlist
- Never allow arbitrary URLs in JWT headers for key resolution

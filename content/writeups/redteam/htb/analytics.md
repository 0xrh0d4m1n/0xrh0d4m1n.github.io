---
title: "Analytics"
date: 2023-12-08
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - Metabase
sidebar:
  hide: true
---

[← Back to HackTheBox Writeups](/writeups/redteam/htb/)

# **Analytics**

![Analytics](https://live.staticflickr.com/65535/53476617765_36e0823f54_c.jpg)

<details>
<summary>ℹ️ Machine Information</summary>

**Machine**: [Analytics](https://app.hackthebox.com/machines/569)  
**Level**: `Easy`  
**Tags**: `Linux`, `Web`, `Metabase`  
**Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/569)

</details>

---

> **Note**: Full writeup content should be copied from `docs/pages/writeups/htb/analytics.md`.

---

## 🚀 **Starting**

```bash
echo '10.10.11.233 analytical.htb' | sudo tee -a /etc/hosts
```

---

## Summary

Metabase running on the machine is vulnerable to **CVE-2023-38646** (pre-auth RCE). After getting a shell in a container environment, escalation to host root is possible through an Ubuntu OverlayFS privilege escalation vulnerability.

---

## 🏁 **Flag Exfiltration**

<details>
<summary>🏁 Reveal Flags</summary>

Copy flags from the original writeup at `docs/pages/writeups/htb/analytics.md`.

</details>

---

_See you in the next writeup!_

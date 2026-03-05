---
title: "Bizness"
date: 2024-01-10
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - Apache OFBiz
---

[← Back to HackTheBox Writeups](/writeups/redteam/htb/)

# **Bizness**

![Bizness](https://live.staticflickr.com/65535/53513263261_2f4f606f86_c.jpg)

<details>
<summary>ℹ️ Machine Information</summary>

**Machine**: [Bizness](https://app.hackthebox.com/machines/582)  
**Level**: `Easy`  
**Tags**: `Linux`, `Web`, `Apache OFBiz`  
**Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/582)

</details>

---

> **Note**: Full writeup content should be copied from `docs/pages/writeups/htb/bizness.md`.

---

## 🚀 **Starting**

```bash
echo '10.10.11.252 bizness.htb' | sudo tee -a /etc/hosts
```

---

## Summary

Apache OFBiz running on the machine is vulnerable to **CVE-2023-49070** (pre-auth RCE) and **CVE-2023-51467** (auth bypass). Exploitation leads to root access through password cracking from the Derby database.

---

## 🏁 **Flag Exfiltration**

<details>
<summary>🏁 Reveal Flags</summary>

Copy flags from the original writeup at `docs/pages/writeups/htb/bizness.md`.

</details>

---

_See you in the next writeup!_

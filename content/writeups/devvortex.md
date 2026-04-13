---
platform: "htb"
category: "redteam"
title: "Devvortex"
date: 2023-11-25
difficulty: "Easy"
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - Joomla
---

[← Back to HackTheBox Writeups](/writeups/redteam/htb/)

# **Devvortex**

![Devvortex](https://live.staticflickr.com/65535/53476413359_5dc2099d85_c.jpg)

<details>
<summary>ℹ️ Machine Information</summary>

**Machine**: [Devvortex](https://app.hackthebox.com/machines/577)  
**Level**: `Easy`  
**Tags**: `Linux`, `Web`, `Joomla`  
**Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/577)

</details>

---

> **Note**: Full writeup content should be copied from `docs/pages/writeups/htb/devvortex.md`.

---

## 🚀 **Starting**

```bash
echo '10.10.11.242 devvortex.htb' | sudo tee -a /etc/hosts
```

---

## Summary

Joomla CMS running on the machine is vulnerable to **CVE-2023-23752** (information disclosure), leaking database credentials. Using those credentials to access Joomla admin panel allows PHP code injection. Privilege escalation via a vulnerable `apport-cli` binary.

---

## 🏁 **Flag Exfiltration**

<details>
<summary>🏁 Reveal Flags</summary>

Copy flags from the original writeup at `docs/pages/writeups/htb/devvortex.md`.

</details>

---

_See you in the next writeup!_

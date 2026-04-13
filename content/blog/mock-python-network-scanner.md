---
title: "Building a Network Scanner in Python"
date: 2025-02-14
description: "Learn how to build a simple yet effective network scanner using Python's socket and scapy libraries for reconnaissance and network mapping."
tags: ["python", "networking", "red-team", "tools", "scripting"]
categories: ["Programming"]
image: "https://picsum.photos/seed/pynet5/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Why Build Your Own Scanner?

While tools like `nmap` are industry standards, building your own network scanner teaches you the **fundamentals of TCP/IP networking** and gives you a customizable tool for specific engagements.

## Basic TCP Port Scanner

```python
import socket
import concurrent.futures
from datetime import datetime

def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Attempt to connect to a specific port on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return {"port": port, "state": "open", "service": service}
    except socket.error:
        pass
    return {"port": port, "state": "closed", "service": ""}

def scan_host(host: str, ports: range, max_workers: int = 100):
    """Scan multiple ports concurrently."""
    print(f"[*] Scanning {host} started at {datetime.now()}")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)
                print(f"  [+] Port {result['port']}/tcp open - {result['service']}")
    return sorted(open_ports, key=lambda x: x["port"])

if __name__ == "__main__":
    target = "192.168.1.1"
    results = scan_host(target, range(1, 1025))
    print(f"\n[*] Found {len(results)} open ports")
```

## Adding ARP Discovery with Scapy

```python
from scapy.all import ARP, Ether, srp

def discover_hosts(network: str) -> list:
    """Discover live hosts on the network using ARP."""
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    return hosts
```

### Sample Output

```json
[
  {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"},
  {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:0a"},
  {"ip": "192.168.1.25", "mac": "aa:bb:cc:dd:ee:19"}
]
```

## Dependencies

Install the required packages:

```bash
pip install scapy
# scapy requires root/admin for raw socket access
sudo python3 scanner.py
```

### Feature Comparison

| Feature | Our Scanner | Nmap | Masscan |
|---------|------------|------|---------|
| TCP Connect | Yes | Yes | Yes |
| SYN Scan | With Scapy | Yes | Yes |
| ARP Discovery | Yes | Yes | No |
| OS Detection | No | Yes | No |
| Speed | Moderate | Moderate | Very Fast |
| Customizable | Fully | Via NSE | Limited |

## Next Steps

- Add **banner grabbing** to identify service versions
- Implement *SYN scanning* with raw sockets for stealth
- Add output formats (JSON, CSV, XML)
- Integrate with a database for tracking scan results over time

> Remember: **always obtain proper authorization** before scanning any network. Unauthorized scanning may violate laws and organizational policies.

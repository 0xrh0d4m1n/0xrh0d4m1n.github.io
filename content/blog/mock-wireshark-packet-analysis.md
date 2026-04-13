---
title: "Wireshark Packet Analysis for Network Forensics"
date: 2024-12-15
description: "Learn to use Wireshark display filters and analysis techniques to investigate suspicious network traffic and identify threats."
tags: ["networking", "forensics", "wireshark", "blue-team", "tools"]
categories: ["Networking"]
image: "https://picsum.photos/seed/shark13/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Wireshark Essentials

Wireshark is the world's most widely used **network protocol analyzer**. For security professionals, it is invaluable for investigating incidents, analyzing malware communication, and understanding network behavior.

## Display Filter Cheat Sheet

### Basic Filters

| Filter | Description |
|--------|-------------|
| `ip.addr == 10.0.0.1` | Traffic to/from specific IP |
| `tcp.port == 443` | HTTPS traffic |
| `dns` | All DNS queries |
| `http.request.method == "POST"` | HTTP POST requests |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | TCP SYN packets (new connections) |
| `frame.len > 1000` | Large packets |
| `tcp.analysis.retransmission` | Retransmitted packets |

### Threat Hunting Filters

```
# Detect potential C2 beaconing (regular interval connections)
tcp.flags.syn == 1 && ip.dst != 10.0.0.0/8

# Find DNS queries for suspicious TLDs
dns.qry.name contains ".xyz" || dns.qry.name contains ".top"

# Detect potential data exfiltration via DNS
dns.qry.name.len > 50

# Find HTTP traffic with encoded payloads
http.request.uri contains "base64" || http.request.uri contains "%3D%3D"

# Identify cleartext credentials
http.request.method == "POST" && http.content_type contains "form"
```

## Common Investigation Scenarios

### Scenario 1: Malware C2 Communication

Steps to identify command-and-control traffic:

1. Filter for **outbound connections** to external IPs
2. Look for *regular interval* connections (beaconing)
3. Check for **unusual ports** or protocols
4. Examine the payload for encoded or encrypted data
5. Cross-reference destination IPs with threat intelligence

### Scenario 2: Data Exfiltration

```bash
# Using tshark (CLI Wireshark) for automated analysis
# Extract all DNS queries
tshark -r capture.pcap -T fields -e dns.qry.name -Y "dns.qry.type == 1" | sort | uniq -c | sort -rn

# Calculate bytes transferred per destination
tshark -r capture.pcap -T fields -e ip.dst -e frame.len -Y "ip.src == 10.0.0.50" | \
  awk '{sum[$1]+=$2} END {for(ip in sum) print ip, sum[ip]}' | sort -k2 -rn

# Extract HTTP objects (files)
tshark -r capture.pcap --export-objects http,exported_files/
```

### Scenario 3: ARP Spoofing Detection

Look for these indicators:

- Multiple IPs claiming the same MAC address
- ARP replies without corresponding requests
- Rapid changes in ARP table entries

```
# Filter for ARP anomalies
arp.duplicate-address-detected || arp.opcode == 2
```

## Protocol Statistics

Use Wireshark's built-in statistics for quick analysis:

- **Statistics > Conversations** -- see top talkers
- **Statistics > Protocol Hierarchy** -- protocol distribution
- **Statistics > Endpoints** -- unique hosts in the capture
- **Statistics > I/O Graphs** -- visualize traffic patterns over time

> When investigating a PCAP, always start with the **protocol hierarchy** to understand what types of traffic are present before diving into individual packets.

## Capture Best Practices

- Use **capture filters** to reduce file size: `host 10.0.0.1 and port 80`
- Set a **ring buffer** for continuous capture: `-b filesize:100000 -b files:10`
- Always capture in *promiscuous mode* for complete visibility
- Document the capture location, time, and purpose for chain of custody

Wireshark mastery comes with practice. Analyze CTF PCAPs and real-world samples from sources like **Malware Traffic Analysis** to sharpen your skills.

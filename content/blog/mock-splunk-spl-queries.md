---
title: "Essential Splunk SPL Queries for SOC Analysts"
date: 2024-11-05
description: "A collection of practical Splunk SPL queries that every SOC analyst should have in their toolkit for daily monitoring and investigation."
tags: ["soc", "splunk", "siem", "threat-hunting", "blue-team", "incident-response"]
categories: ["SOC"]
image: "https://picsum.photos/seed/splunk3/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Why SPL Matters

Splunk Processing Language (SPL) is the backbone of security operations in environments running Splunk as their SIEM. Mastering SPL allows analysts to **hunt threats**, **triage alerts**, and **build dashboards** efficiently.

## Authentication Monitoring

### Failed Login Detection

```bash
index=windows sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, user, dest
| where count > 5
| sort -count
| table src_ip user dest count
```

### Brute Force Identification

```bash
index=windows EventCode=4625
| bin _time span=5m
| stats count as attempts dc(user) as unique_users by src_ip, _time
| where attempts > 20 AND unique_users > 3
| table _time src_ip attempts unique_users
```

## Network Threat Detection

| Use Case | Key Fields | EventCode/Source |
|----------|-----------|-----------------|
| DNS Tunneling | query_length, query_type | dns logs |
| Beaconing | dest_ip, interval | firewall/proxy |
| Data Exfiltration | bytes_out, dest_port | proxy/firewall |
| Port Scanning | dest_port count | network flow |

### Detecting DNS Tunneling

```bash
index=dns
| eval query_length=len(query)
| where query_length > 50
| stats count avg(query_length) as avg_len by src_ip, query_type
| where count > 100 AND avg_len > 60
| sort -count
```

## Process Monitoring

Key things to look for in process creation events:

1. **Unusual parent-child relationships** -- e.g., `excel.exe` spawning `cmd.exe`
2. **Encoded commands** -- Base64 in command line arguments
3. **Living-off-the-land binaries** (LOLBins) -- `certutil`, `mshta`, `regsvr32`
4. **Suspicious paths** -- executables running from `%TEMP%` or `%APPDATA%`

```bash
index=sysmon EventCode=1
| search (parent_process_name="excel.exe" OR parent_process_name="winword.exe")
  AND (process_name="cmd.exe" OR process_name="powershell.exe" OR process_name="wscript.exe")
| table _time host user parent_process_name process_name CommandLine
```

## Dashboarding Tips

> A well-designed SOC dashboard should answer three questions at a glance: *What happened?* *When?* and *How severe is it?*

### Essential Dashboard Panels

- **Top Talkers** -- highest volume source/destination IPs
- **Authentication Failures** -- trending failed logins over time
- **Alert Volume** -- grouped by severity and category
- **Endpoint Health** -- agents reporting vs. silent hosts

```bash
# Quick panel: Top 10 alerting sources in last 24h
index=notable
| stats count by src_ip, rule_name
| sort -count
| head 10
```

Bookmark these queries and customize them for your environment. The best SOC analysts build a **personal query library** that evolves with the threat landscape.

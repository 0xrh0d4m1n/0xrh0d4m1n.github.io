---
platform: "cyberdefenders"
title: "WebStrike"
category: "Network Forensics"
difficulty: "Easy"
date: 2026-04-18
tags:
  - Wireshark
  - Initial Acess
  - Execution
  - Persistence
  - Command and Control
  - Exfiltration
---

# WebStrike Lab

## Description
> Analyze network traffic using Wireshark to investigate a web server compromise, identify web shell deployment, reverse shell communication, and data exfiltration.

## Scenario
> A suspicious file was identified on a company web server, raising alarms within the intranet. The Development team flagged the anomaly, suspecting potential malicious activity. To address the issue, the network team captured critical network traffic and prepared a PCAP file for review.
Your task is to analyze the provided PCAP file to uncover how the file appeared and determine the extent of any unauthorized activity.

## Questions 6/6

### Q1

Identifying the geographical origin of the attack facilitates the implementation of geo-blocking measures and the analysis of threat intelligence. From which city did the attack originate?

_💡 Note: The lab machines do not have internet access. To look up the IP address and complete this step, use an IP geolocation service on your local computer outside the lab environment._

**Answer:**

<spoiler>
test123
</spoiler>

### Q2 

Knowing the attacker's User-Agent assists in creating robust filtering rules. What's the attacker's Full User-Agent?

### Q3

We need to determine if any vulnerabilities were exploited. What is the name of the malicious web shell that was successfully uploaded?

### Q4

Identifying the directory where uploaded files are stored is crucial for locating the vulnerable page and removing any malicious files. Which directory is used by the website to store the uploaded files?

### Q5

Which port, opened on the attacker's machine, was targeted by the malicious web shell for establishing unauthorized outbound communication?

### Q6

Recognizing the significance of compromised data helps prioritize incident response actions. Which file was the attacker attempting to exfiltrate?

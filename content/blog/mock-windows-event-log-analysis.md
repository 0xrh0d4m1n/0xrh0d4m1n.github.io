---
title: "Windows Event Log Analysis for Threat Detection"
date: 2026-01-18
description: "Master Windows Event Log analysis to detect suspicious activity, lateral movement, and persistence mechanisms in enterprise environments."
tags: ["windows", "soc", "blue-team", "incident-response", "forensics", "threat-hunting"]
categories: ["SOC"]
image: "https://picsum.photos/seed/winlog6/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## Critical Event IDs

Windows Event Logs are a goldmine for security analysts. Knowing which **Event IDs** to monitor is the first step toward effective detection.

### Authentication Events

| Event ID | Description | Log Source |
|----------|-------------|-----------|
| 4624 | Successful logon | Security |
| 4625 | Failed logon | Security |
| 4648 | Logon with explicit credentials | Security |
| 4672 | Special privileges assigned | Security |
| 4720 | User account created | Security |
| 4732 | Member added to local group | Security |

### Process and Service Events

| Event ID | Description | Log Source |
|----------|-------------|-----------|
| 4688 | Process creation | Security |
| 7045 | New service installed | System |
| 1 | Process creation (Sysmon) | Sysmon |
| 3 | Network connection (Sysmon) | Sysmon |
| 11 | File created (Sysmon) | Sysmon |

## PowerShell for Log Analysis

```bash
# Query failed logons in the last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=(Get-Date).AddDays(-1)
} | Select-Object TimeCreated,
    @{n='User';e={$_.Properties[5].Value}},
    @{n='Source';e={$_.Properties[19].Value}},
    @{n='LogonType';e={$_.Properties[10].Value}}
```

```bash
# Find new services installed (potential persistence)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    ForEach-Object {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            ServiceName = $_.Properties[0].Value
            ImagePath   = $_.Properties[1].Value
            AccountName = $_.Properties[4].Value
        }
    } | Format-Table -AutoSize
```

## Logon Type Reference

Understanding logon types is *essential* for distinguishing normal activity from suspicious behavior:

1. **Type 2** -- Interactive (local console logon)
2. **Type 3** -- Network (SMB, mapped drives)
3. **Type 4** -- Batch (scheduled tasks)
4. **Type 5** -- Service (service startup)
5. **Type 7** -- Unlock (workstation unlock)
6. **Type 10** -- RemoteInteractive (RDP)

> A logon **Type 10** from an unexpected source IP, especially outside business hours, warrants immediate investigation.

### Suspicious Patterns to Watch

- Multiple `4625` events followed by a `4624` from the same source (brute force success)
- `4648` events indicating *credential reuse* across systems
- `4720` followed by `4732` adding the new user to `Administrators`
- `7045` with services running from `%TEMP%` or `%APPDATA%` paths

## Enabling Enhanced Logging

For effective monitoring, ensure these audit policies are enabled:

```bash
# Enable command-line logging in process creation events
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable PowerShell Script Block Logging via GPO
# Computer Configuration > Administrative Templates > Windows Components
# > Windows PowerShell > Turn on PowerShell Script Block Logging
```

Investing time in understanding Windows Event Logs pays dividends in faster detection and response. Combine these techniques with your SIEM for automated alerting.

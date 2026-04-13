---
title: "Linux Forensics: Essential Commands and Techniques"
date: 2024-07-22
description: "A hands-on guide to Linux forensic investigation covering artifact collection, log analysis, and evidence preservation."
tags: ["forensics", "linux", "incident-response", "blue-team", "dfir"]
categories: ["Security"]
image: "https://picsum.photos/seed/forensic4/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## First Response: Volatile Data Collection

When responding to a potential compromise on a Linux system, **volatile data must be collected first** since it will be lost on reboot. Always work from a *trusted toolkit* on external media.

### System Information

```bash
# Current date and time
date -u

# System uptime
uptime

# Kernel version and hostname
uname -a

# Currently logged-in users
w
who -a

# Running processes with full details
ps auxwwf

# Open network connections
ss -tulnp
netstat -antp
```

### Memory Acquisition

```bash
# Using LiME (Linux Memory Extractor)
sudo insmod lime-$(uname -r).ko "path=/mnt/evidence/memory.lime format=lime"

# Using /proc/kcore (less reliable)
sudo dd if=/proc/kcore of=/mnt/evidence/kcore.img bs=1M
```

## Key Forensic Artifacts

| Artifact | Location | Contains |
|----------|----------|----------|
| Auth logs | `/var/log/auth.log` | Login attempts, sudo usage |
| Syslog | `/var/log/syslog` | General system events |
| Bash history | `~/.bash_history` | User command history |
| Cron jobs | `/etc/crontab`, `/var/spool/cron/` | Scheduled tasks |
| SSH keys | `~/.ssh/authorized_keys` | Authorized remote access |
| Temp files | `/tmp`, `/var/tmp` | Dropped payloads |
| Systemd services | `/etc/systemd/system/` | Persistence mechanisms |

## Timeline Analysis

Building a filesystem timeline is crucial for understanding attacker activity:

```bash
# Create a body file using find
find / -xdev -printf "%T@ %m %u %g %s %p\n" 2>/dev/null | \
  sort -n > /mnt/evidence/timeline.txt

# Using fls from Sleuth Kit on a disk image
fls -r -m "/" /mnt/evidence/disk.img > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv
```

### What to Look For

1. Files modified during the suspected compromise window
2. New files created in `/tmp`, `/dev/shm`, or hidden directories
3. Modified configuration files in `/etc/`
4. Recently installed packages or binaries
5. Changes to cron jobs or systemd units

## Persistence Mechanisms

Check these common persistence locations:

- `/etc/crontab` and user crontabs in `/var/spool/cron/`
- Systemd services: `systemctl list-unit-files --state=enabled`
- RC scripts in `/etc/rc.local`
- Shell profiles: `.bashrc`, `.profile`, `.bash_profile`
- SSH `authorized_keys` for all users
- Kernel modules: `lsmod` and `/etc/modules`

```bash
# Find recently modified files (last 2 days)
find / -xdev -mtime -2 -type f -ls 2>/dev/null

# Check for files with SUID/SGID bits
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls

# Look for hidden files in /tmp
find /tmp -name ".*" -ls
```

> Always maintain a proper **chain of custody** and document every command executed during your investigation. Use `script` to record your terminal session.

Forensic investigations on Linux require patience and methodical approaches. Document everything and preserve the original evidence.

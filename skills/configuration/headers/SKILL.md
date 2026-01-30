---
name: security_headers
description: HTTP Security Headers analysis and testing methodology
version: 1.0.0
tags: [configuration, headers, A05:2021, API8:2023]
---

# Security Headers Testing

## Overview
Missing or misconfigured HTTP security headers can expose applications to various attacks.

## Headers to Check

### Content-Security-Policy (CSP)
**Purpose**: Prevent XSS, clickjacking, code injection

**Issues**:
```
# Missing entirely - Critical
# Overly permissive:
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'

# Recommended:
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
```

### X-Frame-Options
**Purpose**: Prevent clickjacking

**Issues**:
```
# Missing - Medium
# Recommended:
X-Frame-Options: DENY
# Or:
X-Frame-Options: SAMEORIGIN
```

### X-Content-Type-Options
**Purpose**: Prevent MIME type sniffing

**Issues**:
```
# Missing - Low
# Recommended:
X-Content-Type-Options: nosniff
```

### Strict-Transport-Security (HSTS)
**Purpose**: Force HTTPS

**Issues**:
```
# Missing - Medium
# Too short max-age
# Missing includeSubDomains

# Recommended:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### X-XSS-Protection
**Purpose**: Browser XSS filter (deprecated but still useful)

**Issues**:
```
# Missing - Low
# Recommended:
X-XSS-Protection: 1; mode=block
```

### Referrer-Policy
**Purpose**: Control referrer information in requests

**Issues**:
```
# Missing - Info
# Leaking full URL

# Recommended:
Referrer-Policy: strict-origin-when-cross-origin
```

### Permissions-Policy
**Purpose**: Control browser features

**Issues**:
```
# Missing - Low
# Recommended (restrict cameras, microphones, etc.):
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

### Cache-Control
**Purpose**: Prevent caching sensitive data

**Issues for authenticated pages**:
```
# Missing on sensitive pages - Medium
# Recommended:
Cache-Control: no-store, no-cache, must-revalidate, private
```

## CORS Headers

### Access-Control-Allow-Origin
**Issues**:
```
# Overly permissive - High
Access-Control-Allow-Origin: *

# Reflected origin without validation - Critical
Access-Control-Allow-Origin: [reflected from request]

# Null allowed - High
Access-Control-Allow-Origin: null
```

### Access-Control-Allow-Credentials
**Issues**:
```
# Combined with * origin - Critical (won't work but indicates intent)
# Combined with reflected origin - Critical
Access-Control-Allow-Credentials: true
```

## PoC Template
```python
import requests

def analyze_headers(url):
    r = requests.get(url)
    headers = r.headers
    
    issues = []
    
    if 'Content-Security-Policy' not in headers:
        issues.append(("Critical", "Missing CSP header"))
    
    if 'X-Frame-Options' not in headers:
        issues.append(("Medium", "Missing X-Frame-Options"))
    
    if 'Strict-Transport-Security' not in headers:
        issues.append(("Medium", "Missing HSTS"))
    
    cors = headers.get('Access-Control-Allow-Origin')
    if cors == '*':
        issues.append(("High", "Overly permissive CORS"))
    
    return issues
```

## Severity Mapping
| Header | Missing Severity |
|--------|-----------------|
| CSP | Critical/High |
| X-Frame-Options | Medium |
| HSTS | Medium |
| CORS * | High |
| X-Content-Type-Options | Low |
| Referrer-Policy | Info |

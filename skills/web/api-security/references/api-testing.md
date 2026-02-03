# REST API Security Testing Skill

## Goal

Identify and exploit REST API vulnerabilities including broken authentication, injection, and data exposure.

## Methodology

1. **Discover Endpoints:** Enumerate API endpoints via documentation, JavaScript, or fuzzing
2. **Test Authentication:** Verify token handling, session management, API keys
3. **Test Authorization:** Check access controls (IDOR, privilege escalation)
4. **Test Input Validation:** SQL injection, NoSQL injection, XXE in API
5. **Check Rate Limiting:** Test for DoS and brute force possibilities

## API Discovery

```bash
# Common patterns
/api/v1/users
/api/v2/users
/api/users/{id}
/api/admin/users

# Find in JavaScript
grep -r "api" | grep -E "fetch|axios|XMLHttpRequest"

# Swagger/OpenAPI
/swagger.json
/v1/swagger.json
/openapi.json
/api-docs
```

## Authentication Testing

```bash
# Missing authentication
curl https://target.com/api/users -v

# Token manipulation
Authorization: Bearer eyJ...  # Decode and modify JWT
X-API-Key: test123  # Try common/weak keys

# Token in URL (insecure)
/api/users?token=xyz  # Leaks in logs, Referer
```

## Authorization Testing (IDOR)

```bash
# Access other users' resources
GET /api/users/123  # Your ID
GET /api/users/124  # Another user's ID

# Increment IDs, try UUIDs, encoded values
/api/orders/101
/api/orders/102

# UUID prediction
/api/users/550e8400-e29b-41d4-a716-446655440000
/api/users/550e8400-e29b-41d4-a716-446655440001
```

## HTTP Method Testing

```bash
# Try all methods on each endpoint
GET    /api/users/1  # Read
POST   /api/users/1  # Create? Duplicate?
PUT    /api/users/1  # Update (even as non-owner?)
PATCH  /api/users/1  # Partial update
DELETE /api/users/1  # Delete
OPTIONS /api/users/1  # Allowed methods
```

## Mass Assignment

```bash
# Add extra fields to request
POST /api/users
{"username": "test", "role": "admin", "isVerified": true}

# Update protected fields
PATCH /api/users/me
{"balance": 1000000, "permissions": ["admin"]}
```

## API Versioning Bypass

```bash
# Old API versions may lack security controls
/api/v1/admin  # Blocked
/api/v0/admin  # Works!
/api/admin     # No version - default to old?
```

## Parameter Pollution

```bash
# Send same parameter multiple times
/api/transfer?amount=1&to=attacker&amount=1000000
POST: amount=1&amount=1000000
```

## Content-Type Abuse

```bash
# Change content type for injection
Content-Type: application/xml
# Send XML with XXE

Content-Type: text/xml
# May bypass JSON validation
```

## Rate Limiting Bypass

```bash
# Header manipulation
X-Forwarded-For: 127.0.0.1
X-Original-IP: 1.2.3.4
X-Real-IP: 1.2.3.5

# Path variation
/api/login
/Api/Login
/api./login
/api/login/
```

## Tools

* **Burp Suite** - API testing and fuzzing
* **Postman** - API development and testing
* **ffuf** - Endpoint fuzzing
* **wfuzz** - Web fuzzer

## Example Commands

```bash
# Fuzz API endpoints
ffuf -u https://target.com/api/FUZZ -w wordlist.txt

# Test methods
for method in GET POST PUT DELETE PATCH; do
  curl -X $method https://target.com/api/users/1 -v
done
```

## Guidance for AI

* Activate when testing REST APIs
* Start with unauthenticated requests to find exposed data
* Test IDOR by manipulating resource IDs
* Check if API accepts additional fields (mass assignment)
* Verify rate limiting on sensitive endpoints
* Old API versions often have weaker security
* Check API documentation for hidden/deprecated endpoints

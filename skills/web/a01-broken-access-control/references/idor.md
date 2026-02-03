# Insecure Direct Object Reference (IDOR) Skill

## Goal

Identify and exploit IDOR vulnerabilities to access unauthorized data or perform unauthorized actions.

## Methodology

1. **Identify Object References:** Find IDs in URLs, parameters, cookies, or headers
2. **Map Access Patterns:** Understand how objects are identified and accessed
3. **Test Horizontal Access:** Try accessing other users' data at same privilege level
4. **Test Vertical Access:** Try accessing higher-privilege resources
5. **Automate Testing:** Use Burp or scripts to enumerate IDs systematically

## Common IDOR Locations

```bash
# URL path
/api/users/123/profile
/download/invoice/456
/view/document/789

# Query parameters
/api/order?id=123
/getFile?fileId=abc123

# POST body
{"userId": 123, "action": "view"}

# Headers
X-User-ID: 123
Cookie: user_id=123
```

## Testing Techniques

### Sequential IDs
```bash
# Your resource
GET /api/orders/5001

# Try adjacent IDs
GET /api/orders/5000
GET /api/orders/5002
```

### UUID/GUID Testing
```bash
# Collect multiple UUIDs to find patterns
550e8400-e29b-41d4-a716-446655440000
550e8400-e29b-41d4-a716-446655440001  # Sequential?

# Try version 1 UUIDs (contain timestamp/MAC)
```

### Encoded IDs
```bash
# Base64 encoded
/resource/MTIz  # base64("123")
# Decode, modify, re-encode
MTI0  # base64("124")

# Hash-based (try to find pattern)
```

### Parameter Pollution
```bash
/api/user?id=attacker&id=victim
/api/user?id[]=attacker&id[]=victim
```

## Horizontal Privilege Escalation

```bash
# Access other users' data
GET /api/users/100/messages  # Your ID
GET /api/users/101/messages  # Another user

# Modify other users' data
PUT /api/users/101/profile
DELETE /api/users/101/posts
```

## Vertical Privilege Escalation

```bash
# Access admin resources
GET /api/admin/users  # Normally blocked
GET /api/users?role=admin  # Filter parameter

# Function-level access control
POST /api/admin/deleteUser?userId=123
```

## Blind IDOR

```bash
# No direct data returned but action performed
POST /api/subscribe?userId=victim
# Victim gets subscribed without feedback to attacker
```

## Bypass Techniques

```bash
# Wrapping ID
{"userId": {"id": 123}}
{"userId": [123]}

# Parameter name variation
id, user_id, userId, uid, Id

# Path traversal
/api/users/123/../124

# HTTP Parameter Pollution
?id=my_id&id=victim_id
```

## Tools

* **Burp Suite Autorize** - Automated access control testing
* **Burp Intruder** - ID enumeration
* **FFUF** - Fuzzing object references

## Example Commands

```bash
# Enumerate IDs with ffuf
ffuf -u https://target.com/api/users/FUZZ -w ids.txt

# With Burp Intruder (Numbers payload 1-1000)
```

## Guidance for AI

* Activate when testing APIs or applications with object references
* Check every parameter that might reference an object
* Test both read (GET) and write (POST/PUT/DELETE) operations
* Consider encoded, hashed, or UUID-based identifiers
* Don't assume randomness equals security
* Autorize extension helps test access control systematically
* Both horizontal and vertical escalation are valuable findings

---
name: idor
description: Insecure Direct Object Reference testing for broken access control
version: 1.0.0
tags: [authorization, access-control, A01:2021, API1:2023]
---

# IDOR Testing Methodology

## Overview
IDOR occurs when an application uses user-supplied input to access objects directly without proper authorization checks.

## Types
1. **Horizontal IDOR**: Access other users' data at same privilege level
2. **Vertical IDOR**: Access higher privilege resources

## Testing Methodology

### 1. Identify Object References
- Numeric IDs: /api/users/123
- UUIDs: /api/orders/550e8400-e29b-41d4-a716-446655440000
- Encoded IDs: Base64, Hashes
- File names: /documents/report_123.pdf

### 2. Common Endpoints to Test
```
/api/users/{id}
/api/orders/{id}
/api/invoices/{id}
/api/documents/{id}
/api/accounts/{id}
/api/profiles/{id}
/api/messages/{id}
/api/transactions/{id}
```

### 3. ID Manipulation
```
# Numeric
123 → 124, 122, 0, 1, -1, 999999

# Sequential
Replace your ID with another user's ID

# UUID
Generate valid UUID format
Try null UUID: 00000000-0000-0000-0000-000000000000

# Encoded
Decode, modify, re-encode
```

### 4. HTTP Method Tampering
```
GET /api/users/123 → Try with different user ID
PUT /api/users/123 → Try updating another user
DELETE /api/users/123 → Try deleting another user
```

### 5. Parameter Pollution
```
/api/users?id=123&id=456
/api/users?id=123,456
/api/users?id[]=123&id[]=456
```

### 6. JSON Body Manipulation
```json
// Original
{"user_id": 123, "action": "view"}

// Modified
{"user_id": 456, "action": "view"}
```

### 7. Header Manipulation
```
X-User-ID: 456
X-Original-User: 456
```

## PoC Template
```python
import requests

def test_idor(base_url, endpoint, my_id, other_id, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Access own resource
    r1 = requests.get(f"{base_url}{endpoint}/{my_id}", headers=headers)
    
    # Try accessing other user's resource
    r2 = requests.get(f"{base_url}{endpoint}/{other_id}", headers=headers)
    
    if r2.status_code == 200:
        print(f"[+] IDOR found! Accessed user {other_id}'s data")
        print(f"Response: {r2.json()}")
        return True
    return False
```

## Indicators of IDOR
- 200 OK with different user's data
- Response contains PII of other users
- Sensitive data without permission check
- Same response structure but different data

## Impact
- Access other users' personal data
- Modify other users' settings
- Delete other users' resources
- Financial fraud
- Privacy violations

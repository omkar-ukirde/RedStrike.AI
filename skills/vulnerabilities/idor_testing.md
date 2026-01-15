# IDOR Testing Methodology

## Overview
Insecure Direct Object Reference (IDOR) occurs when an application exposes internal object references (like database IDs) without proper authorization checks.

## Common Locations
- User profiles: `/api/users/123`
- Orders: `/api/orders/456`
- Documents: `/files/789.pdf`
- API endpoints with ID parameters

## Methodology

### 1. Identify Object References
Look for patterns in:
- URL paths: `/user/123/profile`
- Query parameters: `?id=123&user_id=456`
- POST/PUT body: `{"user_id": 123}`
- Headers: `X-User-ID: 123`
- Cookies: `session=base64({"user_id":123})`

### 2. Collect Your Object IDs
- Note your user ID, order IDs, document IDs
- Use Burp to log all requests with IDs

### 3. Test Horizontal Access
```
# Your account
GET /api/users/123/details

# Another user (increment/decrement ID)
GET /api/users/124/details
GET /api/users/122/details
```

### 4. Test Vertical Access
```
# Regular user trying admin endpoint
GET /api/admin/users
POST /api/admin/settings
```

### 5. ID Format Variations
```
# Numeric
123, 124, 125

# UUID (try known UUIDs or common patterns)
550e8400-e29b-41d4-a716-446655440000

# Encoded
base64(123), md5(123)

# Hashed (predictable)
hash(user_id + secret)
```

## Testing Techniques

### Parameter Manipulation
```
Original:  GET /api/orders?order_id=1001
Modified:  GET /api/orders?order_id=1002
Modified:  GET /api/orders?order_id=1001&user_id=other_user
```

### Array Parameters
```
GET /api/orders?ids[]=1001&ids[]=1002
GET /api/orders?ids=1001,1002,1003
```

### HTTP Method Variation
```
GET /api/orders/1001   (allowed)
PUT /api/orders/1002   (might work?)
DELETE /api/orders/1002
```

### Parameter Pollution
```
GET /api/orders?id=1001&id=1002
POST with: {"id": "1001", "id": "1002"}
```

## PoC Template
```python
import requests

def test_idor(base_url, endpoint, id_param, your_id, test_ids, cookies):
    """Test for IDOR vulnerabilities."""
    results = []
    
    # Get your resource first
    your_url = f"{base_url}{endpoint}".replace("{id}", str(your_id))
    your_response = requests.get(your_url, cookies=cookies)
    
    for test_id in test_ids:
        test_url = f"{base_url}{endpoint}".replace("{id}", str(test_id))
        response = requests.get(test_url, cookies=cookies)
        
        if response.status_code == 200:
            # Check if we got different user's data
            if str(test_id) in response.text or response.text != your_response.text:
                results.append({
                    "vulnerable": True,
                    "endpoint": test_url,
                    "accessed_id": test_id,
                    "status": response.status_code,
                })
    
    return results

# Usage
results = test_idor(
    base_url="http://target.com",
    endpoint="/api/users/{id}/profile",
    id_param="id",
    your_id=123,
    test_ids=[122, 124, 125, 1, 100],
    cookies={"session": "your_session_cookie"}
)
```

## Indicators of Vulnerability
- Can access other users' data
- No 403/401 for unauthorized access
- Different data returned for different IDs
- Sensitive data exposure

## Impact
- Unauthorized data access
- Data modification/deletion
- Privacy violation
- Account takeover (in severe cases)

## Remediation
- Implement proper authorization checks
- Use indirect references (mapping tables)
- Validate user ownership server-side
- Use UUIDs instead of sequential IDs
- Log and monitor access patterns

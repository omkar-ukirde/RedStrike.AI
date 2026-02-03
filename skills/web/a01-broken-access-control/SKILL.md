---
name: a01-broken-access-control
description: Skills for testing broken access control vulnerabilities including IDOR, CSRF, CORS misconfigurations, and open redirects per OWASP A01:2021.
compatibility: Requires Burp Suite for testing
allowed-tools: burpsuite curl
metadata:
  owasp: A01:2021
  category: web
---

# Broken Access Control (OWASP A01)

Access control enforces policy such that users cannot act outside their intended permissions.

## Skills

- [IDOR](references/idor.md) - Insecure Direct Object Reference exploitation
- [CSRF](references/csrf.md) - Cross-Site Request Forgery attacks
- [CORS Bypass](references/cors-bypass.md) - CORS misconfiguration exploitation
- [Open Redirect](references/open-redirect.md) - URL redirect manipulation

## Quick Reference

| Attack | Risk | Detection |
|--------|------|-----------|
| IDOR | High | Modify object IDs in requests |
| CSRF | Medium | Check for missing/weak tokens |
| CORS | Medium | Test Origin header reflection |
| Open Redirect | Low-Medium | Test redirect parameters |

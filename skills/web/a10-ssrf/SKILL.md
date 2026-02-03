---
name: a10-ssrf
description: Skills for exploiting server-side request forgery and related server-side attacks per OWASP A10:2021.
compatibility: Requires Burp Suite Collaborator
allowed-tools: burpsuite curl ssrfmap
metadata:
  owasp: A10:2021
  category: web
---

# Server-Side Request Forgery (OWASP A10)

Forcing the server to make requests to unintended locations.

## Skills

- [SSRF](references/ssrf.md) - Server-Side Request Forgery
- [WebSocket Attacks](references/websocket-attacks.md) - WebSocket security testing

## Quick Reference

| Target | URL | Impact |
|--------|-----|--------|
| Cloud metadata | 169.254.169.254 | Credentials, keys |
| Internal services | localhost, 127.0.0.1 | Port scan, access |
| File read | file:///etc/passwd | Local files |

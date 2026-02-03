---
name: web
description: Web application security testing skills organized by OWASP Top 10 2021 categories.
metadata:
  version: "1.0"
  category: web
---

# Web Application Security Skills

Comprehensive web application penetration testing skills based on OWASP Top 10 2021.

## Categories

### OWASP Top 10 2021

| Category | Skills |
|----------|--------|
| [A01 - Broken Access Control](a01-broken-access-control/SKILL.md) | IDOR, CSRF, CORS, Open Redirect |
| [A03 - Injection](a03-injection/SKILL.md) | SQL, NoSQL, Command, SSTI, LDAP, XPath |
| [A04 - Insecure Design](a04-insecure-design/SKILL.md) | Race Condition, HPP |
| [A05 - Security Misconfiguration](a05-security-misconfiguration/SKILL.md) | XXE, File Upload, Subdomain Takeover |
| [A06 - Vulnerable Components](a06-vulnerable-components/SKILL.md) | Deserialization |
| [A07 - Auth Failures](a07-auth-failures/SKILL.md) | JWT, OAuth, Session, 2FA |
| [A08 - Data Integrity](a08-data-integrity-failures/SKILL.md) | HTTP Request Smuggling |
| [A10 - SSRF](a10-ssrf/SKILL.md) | SSRF, WebSocket |

### Additional Categories

| Category | Skills |
|----------|--------|
| [XSS](xss/SKILL.md) | Cross-Site Scripting, Clickjacking |
| [API Security](api-security/SKILL.md) | GraphQL, REST API |
| [File Attacks](file-attacks/SKILL.md) | LFI, RFI |

## Quick Reference

| Attack Type | Tool | Detection |
|-------------|------|-----------|
| SQLi | sqlmap | `'`, error-based |
| XSS | burpsuite | `<script>` reflection |
| SSRF | curl | Internal IP access |
| Command Injection | commix | `;`, `\|`, `&&` |

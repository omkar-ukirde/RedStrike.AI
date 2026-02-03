---
name: a05-security-misconfiguration
description: Skills for exploiting security misconfigurations including XXE, file upload, subdomain takeover, and cache issues per OWASP A05:2021.
compatibility: Requires xxeinjector, nuclei
allowed-tools: xxeinjector nuclei burpsuite curl
metadata:
  owasp: A05:2021
  category: web
---

# Security Misconfiguration (OWASP A05)

Missing or improperly configured security controls at any level of the application stack.

## Skills

- [XXE](references/xxe.md) - XML External Entity injection
- [File Upload](references/file-upload.md) - Unrestricted file upload exploitation
- [Subdomain Takeover](references/subdomain-takeover.md) - Dangling DNS exploitation
- [Cache Deception](references/cache-deception.md) - Web cache poisoning attacks

## Quick Reference

| Attack | Target | Impact |
|--------|--------|--------|
| XXE | XML parsers | File read, SSRF, RCE |
| File Upload | Upload endpoints | Webshell, RCE |
| Subdomain Takeover | Dangling DNS | Phishing, cookies |
| Cache Deception | CDN/proxy | Data theft |

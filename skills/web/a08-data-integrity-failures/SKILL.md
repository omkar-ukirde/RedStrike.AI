---
name: a08-data-integrity-failures
description: Skills for exploiting software and data integrity failures including HTTP request smuggling per OWASP A08:2021.
compatibility: Requires Burp Suite
allowed-tools: burpsuite curl
metadata:
  owasp: A08:2021
  category: web
---

# Software and Data Integrity Failures (OWASP A08)

Violations of code and infrastructure integrity assumptions.

## Skills

- [HTTP Request Smuggling](references/http-request-smuggling.md) - Request desync attacks

## Quick Reference

| Technique | Frontend | Backend |
|-----------|----------|---------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | Both with obfuscation | |

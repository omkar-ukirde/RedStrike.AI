---
name: a06-vulnerable-components
description: Skills for exploiting vulnerable and outdated components including insecure deserialization per OWASP A06:2021.
compatibility: Requires ysoserial, phpggc
allowed-tools: ysoserial phpggc burpsuite
metadata:
  owasp: A06:2021
  category: web
---

# Vulnerable and Outdated Components (OWASP A06)

Using components with known vulnerabilities or outdated software.

## Skills

- [Deserialization](references/deserialization.md) - Insecure deserialization exploitation

## Quick Reference

| Language | Tool | Signature |
|----------|------|-----------|
| Java | ysoserial | `rO0AB...` (Base64) |
| PHP | phpggc | `O:4:"...` |
| Python | pickle | `gASV...` (Base64) |
| .NET | ysoserial.net | ViewState |

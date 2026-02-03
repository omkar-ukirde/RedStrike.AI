---
name: xss
description: Skills for Cross-Site Scripting (XSS) and client-side injection attacks including clickjacking.
compatibility: Requires browser and Burp Suite
allowed-tools: burpsuite dalfox xsstrike
metadata:
  category: web
---

# Cross-Site Scripting (XSS)

Injection of malicious scripts into web pages viewed by other users.

## Skills

- [XSS](references/xss.md) - Cross-Site Scripting attacks
- [Clickjacking](references/clickjacking.md) - UI redressing attacks

## Quick Reference

| Type | Location | Example |
|------|----------|---------|
| Reflected | URL params | `<script>alert(1)</script>` |
| Stored | Database | Persistent payload |
| DOM | Client JS | `#<img onerror=alert(1)>` |

---
name: a04-insecure-design
description: Skills for exploiting insecure design patterns including race conditions and parameter pollution per OWASP A04:2021.
compatibility: Requires Burp Suite Turbo Intruder
allowed-tools: burpsuite curl
metadata:
  owasp: A04:2021
  category: web
---

# Insecure Design (OWASP A04)

Flaws in design and architecture that cannot be fixed by proper implementation.

## Skills

- [Race Condition](references/race-condition.md) - Timing-based exploitation
- [Parameter Pollution](references/parameter-pollution.md) - HTTP parameter manipulation

## Quick Reference

| Attack | Target | Technique |
|--------|--------|-----------|
| Race Condition | Financial, limits | Parallel requests |
| HPP | WAF bypass, logic | Duplicate parameters |

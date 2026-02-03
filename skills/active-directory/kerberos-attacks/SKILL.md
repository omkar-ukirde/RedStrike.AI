---
name: kerberos-attacks
description: Skills for Kerberos-based attacks in Active Directory including Kerberoasting and AS-REP Roasting.
metadata:
  category: active-directory
---

# Kerberos Attacks

Kerberos protocol exploitation in Active Directory environments.

## Skills

- [Kerberoast](references/kerberoast.md) - Service account TGS ticket cracking
- [AS-REP Roast](references/asreproast.md) - Pre-auth disabled accounts

## Quick Reference

| Attack | Hash Mode | Target |
|--------|-----------|--------|
| Kerberoast | 13100 (RC4), 19700 (AES256) | Service accounts with SPN |
| AS-REP Roast | 18200 | Accounts without preauth |

---
name: active-directory
description: Active Directory penetration testing skills for Kerberos attacks, enumeration, and lateral movement.
metadata:
  version: "1.0"
  category: active-directory
---

# Active Directory Skills

Comprehensive Active Directory penetration testing skills.

## Categories

| Category | Skills | Focus |
|----------|--------|-------|
| [Kerberos Attacks](kerberos-attacks/SKILL.md) | 2 | Kerberoast, AS-REP Roasting |
| [Enumeration](enumeration/SKILL.md) | 1 | BloodHound, LDAP enum |
| [Lateral Movement](lateral-movement/SKILL.md) | 1 | Pass-the-Hash, PTT |

## Quick Reference

| Attack | Tool | Target |
|--------|------|--------|
| Kerberoast | Rubeus, GetUserSPNs.py | Service accounts |
| AS-REP Roast | Rubeus, GetNPUsers.py | No preauth users |
| DCSync | mimikatz, secretsdump.py | Domain Admin |

---
name: lateral-movement
description: Skills for lateral movement in Active Directory environments using PTH, PTT, and other techniques.
metadata:
  category: active-directory
---

# Lateral Movement

Active Directory lateral movement and credential abuse techniques.

## Skills

- [Credential Attacks](references/credential-attacks.md) - Pass-the-Hash, Pass-the-Ticket, Over-PTH

## Quick Reference

| Technique | Credential | Tool |
|-----------|------------|------|
| PTH | NT hash | mimikatz, crackmapexec |
| PTT | Kerberos ticket | mimikatz, Rubeus |
| Over-PTH | NT hash → TGT | mimikatz |

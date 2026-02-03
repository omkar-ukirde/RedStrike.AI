---
name: email
description: Skills for attacking email services including SMTP, POP3, and IMAP.
compatibility: Requires smtp-user-enum, hydra
allowed-tools: smtp-user-enum hydra nc telnet
metadata:
  category: network
---

# Email Services

Email protocol exploitation and enumeration.

## Skills

- [SMTP Pentesting](references/smtp-pentesting.md) - SMTP (25/465/587)
- [POP3 Pentesting](references/pop3-pentesting.md) - POP3 (110/995)
- [IMAP Pentesting](references/imap-pentesting.md) - IMAP (143/993)

## Quick Reference

| Protocol | Port | Key Attack |
|----------|------|------------|
| SMTP | 25 | User enum, open relay |
| POP3 | 110 | Brute force, read mail |
| IMAP | 143 | Brute force, search mail |

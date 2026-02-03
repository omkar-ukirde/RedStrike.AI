---
name: security-analysis
description: Skills for security analysis including SSL/TLS testing, protocol detection, and evasion techniques.
compatibility: Requires testssl, nmap
allowed-tools: testssl nmap sslscan
metadata:
  category: network
---

# Security Analysis

Security assessment and evasion techniques.

## Skills

- [SSL/TLS Analysis](references/ssl-tls-analysis.md) - Certificate and cipher testing
- [Plaintext Protocol Detection](references/plaintext-protocol-detection.md) - Unencrypted service detection
- [IDS/IPS Evasion](references/ids-ips-evasion.md) - Detection bypass

## Quick Reference

| Analysis | Tool | Purpose |
|----------|------|---------|
| SSL/TLS | testssl.sh | Cipher/cert audit |
| Plaintext | nmap | Service detection |
| Evasion | nmap -f | Fragmentation |

# SSL/TLS Analysis Skill

## Goal

Analyze SSL/TLS configurations to identify weak ciphers, outdated protocols, certificate issues, and cryptographic vulnerabilities.

## Methodology

1. **Certificate Analysis**: Check validity, chain, and configuration
2. **Protocol Detection**: Identify supported TLS versions
3. **Cipher Suite Analysis**: Check for weak ciphers
4. **Vulnerability Scanning**: Test for known SSL vulnerabilities
5. **Configuration Assessment**: Evaluate overall security posture

## Tools

* **testssl.sh**: Comprehensive SSL/TLS testing
* **sslscan**: SSL cipher scanner
* **nmap**: SSL scripts
* **openssl**: Manual testing
* **sslyze**: Python SSL scanner

## Example Commands

### OpenSSL Manual Testing

```bash
# Check certificate
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -text

# Certificate dates
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -dates

# Certificate chain
openssl s_client -showcerts -connect target:443 < /dev/null

# Check specific TLS version
openssl s_client -tls1 -connect target:443       # TLS 1.0
openssl s_client -tls1_1 -connect target:443     # TLS 1.1
openssl s_client -tls1_2 -connect target:443     # TLS 1.2
openssl s_client -tls1_3 -connect target:443     # TLS 1.3

# Check for SSLv3 (POODLE)
openssl s_client -ssl3 -connect target:443

# Check specific cipher
openssl s_client -cipher 'DES-CBC3-SHA' -connect target:443
```

### testssl.sh

```bash
# Full test
./testssl.sh target:443

# Quick test
./testssl.sh --fast target:443

# Specific tests
./testssl.sh --protocols target:443
./testssl.sh --ciphers target:443
./testssl.sh --vulnerable target:443
./testssl.sh --headers target:443

# Test STARTTLS
./testssl.sh --starttls smtp target:25
./testssl.sh --starttls imap target:143
./testssl.sh --starttls pop3 target:110

# JSON output
./testssl.sh --jsonfile output.json target:443
```

### sslscan

```bash
# Basic scan
sslscan target:443

# No color (for parsing)
sslscan --no-colour target:443

# Show certificate
sslscan --show-certificate target:443

# STARTTLS
sslscan --starttls-smtp target:25
sslscan --starttls-imap target:143
```

### Nmap SSL Scripts

```bash
# SSL enumeration
nmap -p 443 --script ssl-enum-ciphers target

# SSL certificate
nmap -p 443 --script ssl-cert target

# SSL known CVEs
nmap -p 443 --script ssl-heartbleed target
nmap -p 443 --script ssl-poodle target
nmap -p 443 --script ssl-dh-params target
nmap -p 443 --script ssl-ccs-injection target

# All SSL scripts
nmap -p 443 --script "ssl-*" target

# Multiple SSL ports
nmap -p 443,465,993,995,3306,5432 --script ssl-enum-ciphers target
```

### sslyze

```bash
# Full scan
sslyze target:443

# Specific tests
sslyze --certinfo target:443
sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 target:443
sslyze --heartbleed target:443
sslyze --robot target:443
sslyze --openssl_ccs target:443
```

## Common Vulnerabilities

| Vulnerability | CVE | Test |
|--------------|-----|------|
| Heartbleed | CVE-2014-0160 | `--heartbleed` |
| POODLE | CVE-2014-3566 | SSLv3 enabled |
| BEAST | CVE-2011-3389 | TLS 1.0 + CBC |
| CRIME | CVE-2012-4929 | TLS compression |
| BREACH | CVE-2013-3587 | HTTP compression |
| FREAK | CVE-2015-0204 | Export ciphers |
| Logjam | CVE-2015-4000 | Weak DH params |
| DROWN | CVE-2016-0800 | SSLv2 enabled |
| ROBOT | CVE-2017-13099 | RSA key exchange |
| Ticketbleed | CVE-2016-9244 | Session ticket |

## Weak Configuration Indicators

```bash
# Deprecated protocols
SSLv2, SSLv3, TLS 1.0, TLS 1.1

# Weak ciphers
NULL, EXPORT, DES, RC4, 3DES, MD5

# Weak key exchange
DH < 2048 bits, RSA key exchange

# Certificate issues
Self-signed
Expired
Wrong hostname
Weak signature (MD5, SHA1)
Short key (< 2048 bits)
No chain

# Missing security headers
HSTS
Certificate Transparency
```

## Severity Ratings

| Finding | Severity |
|---------|----------|
| SSLv2/SSLv3 enabled | Critical |
| Heartbleed vulnerable | Critical |
| TLS 1.0 enabled | Medium |
| TLS 1.1 enabled | Low-Medium |
| 3DES ciphers | Low |
| RC4 ciphers | Medium |
| Expired certificate | Medium |
| Self-signed cert | Low |
| Missing HSTS | Low |
| Weak DH params | Medium |

## Guidance for AI

* Activate this skill to analyze SSL/TLS security
* **testssl.sh is the most comprehensive tool**
* Check ALL SSL-enabled ports (443, 465, 993, 995, 3306, 5432, 8443...)
* Key areas:
  1. Protocol versions supported
  2. Cipher suites offered
  3. Certificate validity/trust
  4. Known vulnerabilities
* Report deprecated protocols (TLS 1.0, 1.1)
* Report weak ciphers (RC4, 3DES, NULL, EXPORT)
* Check certificate matches hostname
* Note expiration dates
* Modern config: TLS 1.2+ only, AEAD ciphers

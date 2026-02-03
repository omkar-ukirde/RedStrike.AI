# Banner Grabbing Skill

## Goal

Extract service banners from network services to identify software versions, configurations, and potential vulnerabilities.

## Methodology

1. **Discovery**: Identify open ports
2. **Banner Extraction**: Connect and capture banners
3. **Version Analysis**: Identify software and versions
4. **Vulnerability Mapping**: Map versions to known CVEs
5. **Information Leakage**: Identify sensitive info in banners

## Tools

* **nc/netcat**: Basic banner grabbing
* **nmap**: Banner scripts
* **telnet**: Interactive banner grabbing
* **curl**: HTTP/S headers
* **openssl**: SSL/TLS banner grabbing

## Example Commands

### Netcat Banner Grabbing

```bash
# Basic TCP banner grab
nc -v target 22
nc -v target 21
nc -v target 25
nc -v target 80

# With timeout
nc -w 3 -v target 22

# Send request for HTTP
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc target 80

# Multiple ports
for port in 21 22 23 25 80 110 143 443 3306 5432; do
    echo "=== Port $port ==="
    nc -w 2 -v target $port 2>&1 | head -5
done
```

### Nmap Banner Grabbing

```bash
# Banner script
nmap -sV --script banner target

# Specific port
nmap -sV --script banner -p 22,80,443 target

# Aggressive version detection
nmap -sV --version-intensity 5 target

# All banner scripts
nmap -sV --script "banner or http-headers or ssh-hostkey" target
```

### HTTP Headers

```bash
# Using curl
curl -I http://target
curl -I -k https://target
curl -sI http://target | grep -i "server\|x-powered-by\|x-aspnet"

# Using wget
wget --server-response --spider http://target 2>&1 | grep -i server

# Using nmap
nmap -p80 --script http-headers target
nmap -p443 --script http-headers target
```

### SSL/TLS Banner

```bash
# Using openssl
echo | openssl s_client -connect target:443 2>/dev/null | head -20

# Get certificate info
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates

# SMTP with STARTTLS
openssl s_client -starttls smtp -connect target:25
openssl s_client -starttls smtp -connect target:587

# IMAP/POP3
openssl s_client -connect target:993
openssl s_client -connect target:995
```

### Service-Specific Banners

```bash
# SSH
ssh -v target 2>&1 | grep "remote software version"
nc target 22

# FTP
nc target 21
echo "QUIT" | nc target 21

# SMTP
nc target 25
echo "EHLO test" | nc target 25

# MySQL
nc target 3306 | strings | head -5

# PostgreSQL
nc target 5432

# DNS
dig version.bind CHAOS TXT @target
dig hostname.bind CHAOS TXT @target
```

## Information in Banners

```bash
# Common sensitive info:
# - Software name and version
# - Operating system
# - Hostname
# - Internal IP addresses
# - Build dates
# - Patch levels
# - Configuration details

# Examples:
# SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
# Apache/2.4.41 (Ubuntu)
# Microsoft-IIS/10.0
# nginx/1.18.0
# 220 mail.example.com ESMTP Postfix
# MySQL 5.7.33-0ubuntu0.18.04.1
```

## Security Implications

| Finding | Severity | Impact |
|---------|----------|--------|
| Outdated version | Medium-High | Known CVEs exploitable |
| Internal hostname | Low | Information disclosure |
| Verbose error messages | Low | Debug info exposure |
| OS fingerprint | Informational | Attack surface mapping |

## Guidance for AI

* Activate this skill to identify service versions and configurations
* **Banner data is critical for vulnerability mapping**
* Capture banners for ALL open ports
* Look for:
  - Software versions (map to CVEs)
  - OS information
  - Internal hostnames
  - Configuration details
* HTTP headers often reveal:
  - Server software
  - X-Powered-By (framework)
  - X-AspNet-Version
* Compare versions against CVE databases
* Document all version info for reporting
* Even "low" info can be used in social engineering

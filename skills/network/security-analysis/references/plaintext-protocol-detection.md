# Plaintext Protocol Detection Skill

## Goal

Identify services using unencrypted/plaintext protocols that expose sensitive data in transit.

## Methodology

1. **Service Identification**: Enumerate all network services
2. **Protocol Analysis**: Determine if encryption is used
3. **Traffic Analysis**: Verify plaintext transmission
4. **Risk Assessment**: Evaluate data exposure risk
5. **Alternative Check**: Verify encrypted alternatives exist

## Plaintext vs Encrypted Protocols

| Plaintext | Port | Encrypted Alternative | Port |
|-----------|------|----------------------|------|
| HTTP | 80 | HTTPS | 443 |
| FTP | 21 | FTPS/SFTP | 990/22 |
| Telnet | 23 | SSH | 22 |
| SMTP | 25 | SMTPS/STARTTLS | 465/587 |
| POP3 | 110 | POP3S | 995 |
| IMAP | 143 | IMAPS | 993 |
| LDAP | 389 | LDAPS | 636 |
| MySQL | 3306 | MySQL+SSL | 3306 |
| PostgreSQL | 5432 | PostgreSQL+SSL | 5432 |
| Redis | 6379 | Redis+TLS | 6379 |
| MongoDB | 27017 | MongoDB+TLS | 27017 |
| Memcached | 11211 | (No native TLS) | - |
| VNC | 5900 | VNC over SSH | - |
| rsh/rlogin | 512-514 | SSH | 22 |

## Detection Commands

```bash
# Check for plaintext HTTP
curl -I http://target 2>&1 | head -5

# Check if HTTPS redirects from HTTP
curl -I -L http://target 2>&1 | grep -i "location\|HTTP"

# Check for plaintext SMTP
nc -w 3 target 25
echo "EHLO test" | nc -w 3 target 25

# Check for plaintext FTP
nc -w 3 target 21

# Check for plaintext IMAP
nc -w 3 target 143

# Check for plaintext POP3
nc -w 3 target 110

# Check for plaintext Telnet
nc -w 3 target 23

# Check MySQL SSL support
mysql -h target -u root --ssl-mode=REQUIRED 2>&1

# Check PostgreSQL SSL
psql "host=target sslmode=require" 2>&1
```

## Nmap Detection

```bash
# Identify plaintext services
nmap -sV -p 21,23,25,80,110,143,389,3306,5432 target

# Check for STARTTLS support
nmap -p 25,587 --script smtp-commands target
nmap -p 143 --script imap-capabilities target
nmap -p 110 --script pop3-capabilities target

# Check if MySQL supports SSL
nmap -p 3306 --script mysql-info target | grep -i ssl
```

## Traffic Capture Analysis

```bash
# Capture plaintext traffic (MITM position)
tcpdump -i eth0 -A 'port 80 or port 21 or port 23 or port 25'

# Filter for credentials
tcpdump -i eth0 -A 'port 21' | grep -i "user\|pass"
tcpdump -i eth0 -A 'port 110' | grep -i "user\|pass"

# HTTP basic auth capture
tcpdump -i eth0 -A 'port 80' | grep -i "authorization"
```

## Security Implications

| Protocol | Risk | Data at Risk |
|----------|------|--------------|
| HTTP | High | Credentials, cookies, session tokens |
| FTP | High | Credentials, file contents |
| Telnet | Critical | Shell credentials, commands |
| SMTP (25) | Medium | Email content, credentials |
| POP3/IMAP | High | Email credentials, content |
| Databases | Critical | Query data, credentials |
| VNC | High | Screen content, credentials |

## Reporting Template

### Finding: Plaintext [Protocol] Exposed

**Severity:** [Critical/High/Medium]

**Description:**
The service [name] on port [port] transmits data in plaintext without encryption.

**Impact:**
- Credentials transmitted in cleartext
- Sensitive data exposed to network eavesdropping
- Man-in-the-middle attacks possible
- Compliance violations (PCI-DSS, HIPAA, GDPR)

**Recommendation:**
- Disable plaintext protocol
- Enable encrypted alternative ([HTTPS/SFTP/etc.])
- Enforce STARTTLS where supported
- Use VPN/SSH tunneling if native encryption unavailable

## Guidance for AI

* Activate this skill to identify unencrypted services
* **Any plaintext service is a finding** - severity based on data exposed
* Check if STARTTLS is supported for SMTP/IMAP/POP3
* Check if SSL/TLS mode available for databases
* HTTP without HTTPS redirect is always a finding
* Telnet, FTP, rsh should never be exposed
* Consider compliance: PCI-DSS prohibits many plaintext protocols
* Even if encrypted version exists, plaintext being enabled is a risk
* Check for HTTP→HTTPS redirect and HSTS header

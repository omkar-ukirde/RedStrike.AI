# RedStrike.AI Skills (Knowledge Base)

A comprehensive collection of AI-powered penetration testing skills following the [Agent Skills](https://agentskills.io) open standard.

## Overview

| Category | Skills | Description |
|----------|--------|-------------|
| Web | 32 | OWASP-organized web application skills |
| Network | 66 | Service-based network penetration testing |
| Mobile | 3 | Android & iOS security testing |
| Active Directory | 4 | Kerberos, enumeration, lateral movement |
| Injection | 7 | SQLi, XSS, SSTI, SSRF, XXE, LFI, RCE |
| Authentication | 2 | IDOR, JWT testing |
| Configuration | 2 | CORS, security headers |
| Logic | 1 | Race conditions |
| **Total** | **~117** | |

---

## Structure

```
skills/
├── web/                        # OWASP-organized web skills
│   ├── SKILL.md
│   ├── a01-broken-access-control/
│   ├── a03-injection/
│   ├── a07-auth-failures/
│   ├── a10-ssrf/
│   └── ...
├── network/                    # Service-based network skills
│   ├── SKILL.md
│   ├── reconnaissance/
│   ├── databases/
│   ├── containers/
│   └── ...
├── mobile/                     # Mobile security skills
│   ├── android/
│   └── ios/
├── active-directory/           # AD attack skills
│   ├── kerberos-attacks/
│   ├── enumeration/
│   └── lateral-movement/
├── injection/                  # Injection testing
├── authentication/             # Auth bypass techniques
├── configuration/              # Misconfig testing
└── logic/                      # Business logic flaws
```

---

## Web Application Skills (32 skills)

| Category | Skills |
|----------|--------|
| A01 - Broken Access Control | IDOR, CSRF, CORS, Privilege Escalation |
| A03 - Injection | SQLi, NoSQL, Command, SSTI, LDAP, XPath, ORM, CRLF |
| A04 - Insecure Design | Business Logic, Race Conditions |
| A05 - Security Misconfiguration | Debug Endpoints, Stack Traces, HTTP Methods |
| A06 - Vulnerable Components | Dependency Scanning |
| A07 - Auth Failures | JWT, OAuth, Session, 2FA Bypass, Password Reset |
| A08 - Data Integrity | Deserialization |
| A10 - SSRF | Cloud Metadata, Internal SSRF |
| XSS | Stored, DOM-based |
| API Security | GraphQL, REST |
| File Attacks | File Upload |

---

## Network Service Skills (66 skills)

| Category | Skills |
|----------|--------|
| Reconnaissance | Port Scanning, Service Detection, Banner Grabbing |
| Layer 2 Attacks | ARP Spoofing, VLAN Hopping, LLMNR Poisoning |
| Auth Services | SSH, RDP, Kerberos, VNC, LDAP |
| File Services | SMB, NFS, FTP, TFTP, WebDAV, Rsync |
| Databases | MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB |
| Email | SMTP, POP3, IMAP |
| Infrastructure | DNS, SNMP, IPMI, RPC, NTP, DHCP |
| Containers | Docker, Kubernetes, Etcd |
| Message Queues | MQTT, RabbitMQ, Kafka |
| Industrial IoT | Modbus, BACnet, OPC-UA, S7comm |
| VPN/Tunneling | IPSec, Pivoting |
| Security Analysis | SSL/TLS, IDS Evasion |
| Wireless | WiFi Attacks |

---

## Mobile Skills (3 skills)

| Category | Skills |
|----------|--------|
| Android | Static Analysis, Dynamic Analysis |
| iOS | Security Testing |

---

## Active Directory Skills (4 skills)

| Category | Skills |
|----------|--------|
| Kerberos Attacks | Kerberoasting, AS-REP Roasting |
| Enumeration | BloodHound |
| Lateral Movement | Pass-the-Hash |

---

## Agent Skills Format

Each skill folder follows the standard:
- **`SKILL.md`** - Required entrypoint with YAML frontmatter
- **`references/`** - Detailed skill files
- **`scripts/`** - Optional automation scripts

## Contributing

Skills can be community-contributed. Follow the format and submit a PR.

## Disclaimer

⚠️ **These skills are for authorized security testing only.**

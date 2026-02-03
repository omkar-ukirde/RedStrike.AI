# Attack Surface Assessment Skill

## Goal

Identify and document all internet-exposed services to assess the attack surface and recommend minimization.

## Methodology

1. **Service Enumeration**: Identify all exposed ports and services
2. **Necessity Assessment**: Determine if each service needs to be public
3. **Risk Classification**: Categorize services by risk level
4. **Exposure Analysis**: Identify unnecessary exposure
5. **Recommendations**: Suggest access restrictions

## Service Categorization

### Should Be Public (Web-facing)
- HTTP/HTTPS (80, 443) - Web applications
- DNS (53) - Public DNS servers only
- SMTP (25) - Mail servers only

### Should Be Restricted (Internal Only)
- SSH (22) - Admin access only via VPN/bastion
- Databases (3306, 5432, 27017) - Never public
- Redis/Memcached (6379, 11211) - Never public
- RDP (3389) - Never public
- Admin panels - Never public

### Should Not Exist
- Telnet (23) - Replace with SSH
- FTP (21) - Replace with SFTP
- rsh/rlogin (512-514) - Obsolete

## Commands for Assessment

```bash
# Full port scan
nmap -p- --min-rate 1000 target

# Quick top 1000
nmap --top-ports 1000 -sV target

# Service identification
nmap -sV -sC target

# Check specific high-risk ports
nmap -p 22,23,25,53,80,110,143,443,445,1433,3306,3389,5432,5900,6379,8080,27017 -sV target
```

## Risk Classification

| Port | Service | Public Exposure | Risk if Exposed |
|------|---------|-----------------|-----------------|
| 22 | SSH | Limit to VPN | Medium |
| 23 | Telnet | Never | Critical |
| 25 | SMTP | Mail servers | Low |
| 53 | DNS | DNS servers | Medium |
| 80/443 | HTTP/S | Web only | Low |
| 110/143 | POP3/IMAP | Limited | Medium |
| 135/445 | SMB/RPC | Never | Critical |
| 1433 | MSSQL | Never | Critical |
| 3306 | MySQL | Never | Critical |
| 3389 | RDP | Never | Critical |
| 5432 | PostgreSQL | Never | Critical |
| 5900 | VNC | Never | High |
| 6379 | Redis | Never | Critical |
| 8080 | HTTP Alt | Carefully | Medium |
| 27017 | MongoDB | Never | Critical |

## Assessment Questions

For each exposed service, ask:
1. **Does this need to be internet-facing?**
2. **Who needs access?**
3. **Can it be accessed via VPN instead?**
4. **Is authentication required?**
5. **Is the software up to date?**
6. **Is encryption enabled?**

## Internet-Facing Services Audit

```bash
# External perspective scan (from outside the network)
nmap -Pn -sV --top-ports 1000 target

# Compare with internal scan to find filtering gaps

# Check Shodan/Censys for historical exposure
# shodan host target_ip
```

## Reporting Template

### Finding: Excessive Attack Surface

**Severity:** Medium-High

**Description:**
The following services are exposed to the internet but do not require public access:
- MySQL (3306)
- PostgreSQL (5432)
- SSH (22)
- [List all]

**Impact:**
- Increased attack surface
- Brute-force attack vectors
- Potential for exploitation
- Data breach risk

**Recommendation:**
1. Configure firewall to restrict access to trusted IPs
2. Use VPN for administrative access
3. Disable unnecessary services
4. Implement network segmentation

## Guidance for AI

* Activate this skill to assess attack surface of target
* **Databases exposed = Critical finding always**
* Each unnecessary service = increased risk
* Key questions:
  - Why is this exposed?
  - Who needs access?
  - Can we restrict it?
* Environment context matters:
  - External server: Minimize exposure
  - Internal server: May have more services
* Recommend principle of least exposure
* Common mistakes:
  - Database ports open to 0.0.0.0
  - Admin interfaces exposed
  - Debug ports left open
  - Test services in production

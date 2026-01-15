# Subdomain Enumeration Methodology

## Overview
Subdomain enumeration discovers all subdomains of a target domain, expanding the attack surface.

## Techniques

### 1. Passive Enumeration
Uses public sources without directly contacting target.

**Certificate Transparency**
```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
```

**Search Engines**
```
site:*.example.com
site:example.com -www
```

**Public Datasets**
- VirusTotal
- SecurityTrails
- Shodan
- Censys

### 2. Active Enumeration
Direct DNS queries and brute-forcing.

**DNS Brute-force**
```bash
# Using subfinder
subfinder -d example.com -silent

# Using amass
amass enum -passive -d example.com

# Using gobuster
gobuster dns -d example.com -w wordlist.txt
```

**DNS Zone Transfer (if misconfigured)**
```bash
dig axfr @ns1.example.com example.com
```

### 3. Permutation/Alteration
Generate variations of known subdomains.

```
# Known: dev.example.com
# Try:
dev1.example.com
dev2.example.com
dev-api.example.com
api-dev.example.com
staging-dev.example.com
```

## Wordlists

**Recommended SecLists paths:**
```
/wordlists/Discovery/DNS/subdomains-top1million-5000.txt
/wordlists/Discovery/DNS/subdomains-top1million-20000.txt
/wordlists/Discovery/DNS/subdomains-top1million-110000.txt
/wordlists/Discovery/DNS/fierce-hostlist.txt
```

## Tool Commands

### Subfinder
```bash
# Basic enumeration
subfinder -d example.com -o subdomains.txt

# With specific sources
subfinder -d example.com -sources crtsh,virustotal,shodan

# Recursive enumeration
subfinder -d example.com -recursive
```

### Amass
```bash
# Passive
amass enum -passive -d example.com

# Active with brute-force
amass enum -active -d example.com -brute

# With config file
amass enum -config amass.ini -d example.com
```

### HTTPX (verify live hosts)
```bash
# Check which subdomains are live
cat subdomains.txt | httpx -silent -status-code

# With technology detection
cat subdomains.txt | httpx -tech-detect
```

## PoC Template
```python
import subprocess
import json

def enumerate_subdomains(domain):
    """Enumerate subdomains using subfinder."""
    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True,
        text=True
    )
    
    subdomains = [s.strip() for s in result.stdout.split("\n") if s.strip()]
    
    return {
        "domain": domain,
        "subdomains": subdomains,
        "count": len(subdomains)
    }

def check_live_hosts(subdomains):
    """Check which subdomains are live."""
    input_data = "\n".join(subdomains)
    result = subprocess.run(
        ["httpx", "-silent"],
        input=input_data,
        capture_output=True,
        text=True
    )
    
    live_hosts = [h.strip() for h in result.stdout.split("\n") if h.strip()]
    return live_hosts

# Usage
subs = enumerate_subdomains("example.com")
live = check_live_hosts(subs["subdomains"])
print(f"Found {len(subs)} subdomains, {len(live)} are live")
```

## Post-Enumeration Steps
1. Filter live hosts with httpx
2. Screenshot with gowitness/eyewitness
3. Port scan interesting targets
4. Technology fingerprinting
5. Check for subdomain takeover

## High-Value Subdomains to Look For
- `admin.`, `administrator.`
- `api.`, `api-dev.`, `api-staging.`
- `dev.`, `development.`, `staging.`
- `test.`, `qa.`, `uat.`
- `jenkins.`, `gitlab.`, `jira.`
- `vpn.`, `remote.`, `gateway.`
- `mail.`, `webmail.`, `email.`
- `ftp.`, `sftp.`, `backup.`

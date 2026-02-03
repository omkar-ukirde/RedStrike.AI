---
name: api-security
description: Skills for testing API security including GraphQL and REST API vulnerabilities.
compatibility: Requires Burp Suite, Postman
allowed-tools: burpsuite postman graphql-cop inql
metadata:
  category: web
---

# API Security

Testing REST and GraphQL API endpoints for vulnerabilities.

## Skills

- [GraphQL Attacks](references/graphql-attacks.md) - GraphQL-specific vulnerabilities
- [API Testing](references/api-testing.md) - REST API security testing

## Quick Reference

| API Type | Common Issues | Tools |
|----------|---------------|-------|
| REST | IDOR, Auth, Mass Assignment | Burp, Postman |
| GraphQL | Introspection, DoS, Auth | InQL, graphql-cop |

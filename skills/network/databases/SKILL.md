---
name: databases
description: Skills for attacking database services including SQL, NoSQL, and in-memory databases.
compatibility: Requires database clients, impacket
allowed-tools: mysql psql mssqlclient.py mongo redis-cli
metadata:
  category: network
---

# Database Services

Database server exploitation and data extraction.

## Skills

- [MySQL Pentesting](references/mysql-pentesting.md) - MySQL/MariaDB (3306)
- [PostgreSQL Pentesting](references/postgresql-pentesting.md) - PostgreSQL (5432)
- [MSSQL Pentesting](references/mssql-pentesting.md) - SQL Server (1433)
- [Oracle Pentesting](references/oracle-pentesting.md) - Oracle DB (1521)
- [MongoDB Pentesting](references/mongodb-pentesting.md) - MongoDB (27017)
- [Redis Pentesting](references/redis-pentesting.md) - Redis (6379)
- [CouchDB Pentesting](references/couchdb-pentesting.md) - CouchDB (5984)
- [Elasticsearch Pentesting](references/elasticsearch-pentesting.md) - Elasticsearch (9200)
- [Memcached Pentesting](references/memcached-pentesting.md) - Memcached (11211)
- [Cassandra Pentesting](references/cassandra-pentesting.md) - Cassandra (9042)
- [InfluxDB Pentesting](references/influxdb-pentesting.md) - InfluxDB (8086)

## Quick Reference

| Database | Port | RCE Method |
|----------|------|------------|
| MySQL | 3306 | UDF |
| MSSQL | 1433 | xp_cmdshell |
| PostgreSQL | 5432 | COPY TO |
| Redis | 6379 | Module load |

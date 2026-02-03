---
name: infrastructure
description: Skills for attacking network infrastructure services including DNS, SNMP, NTP, and RPC.
compatibility: Requires dnsrecon, snmpwalk, rpcinfo
allowed-tools: dnsrecon snmpwalk rpcinfo dig
metadata:
  category: network
---

# Network Infrastructure

Core network infrastructure service exploitation.

## Skills

- [DNS Pentesting](references/dns-pentesting.md) - DNS enumeration (53)
- [SNMP Pentesting](references/snmp-pentesting.md) - SNMP information (161/162)
- [NTP Pentesting](references/ntp-pentesting.md) - NTP attacks (123)
- [RPCBind Pentesting](references/rpcbind-pentesting.md) - RPC enumeration (111)
- [NetBIOS Pentesting](references/netbios-pentesting.md) - Windows naming (137-139)
- [MSRPC Pentesting](references/msrpc-pentesting.md) - Microsoft RPC (135)

## Quick Reference

| Service | Port | Key Attack |
|---------|------|------------|
| DNS | 53 | Zone transfer |
| SNMP | 161 | Community strings |
| NTP | 123 | Monlist amplification |
| RPC | 111 | Service enum |

---
name: layer2-attacks
description: Skills for Layer 2 network attacks including ARP spoofing, DHCP attacks, and VLAN hopping.
compatibility: Requires arpspoof, bettercap, responder
allowed-tools: arpspoof bettercap responder ettercap
metadata:
  category: network
---

# Layer 2 Attacks

Attacks targeting the data link layer for MITM and credential capture.

## Skills

- [ARP Spoofing](references/arp-spoofing.md) - ARP cache poisoning
- [DHCP Attacks](references/dhcp-attacks.md) - DHCP starvation and rogue server
- [LLMNR/NBT-NS Poisoning](references/llmnr-nbt-ns-poisoning.md) - Local name resolution attacks
- [VLAN Hopping](references/vlan-hopping.md) - VLAN segmentation bypass
- [IPv6 Attacks](references/ipv6-attacks.md) - IPv6 exploitation

## Quick Reference

| Attack | Tool | Result |
|--------|------|--------|
| ARP Spoof | arpspoof | MITM |
| LLMNR | Responder | Hashes |
| DHCP | Yersinia | DoS/MITM |

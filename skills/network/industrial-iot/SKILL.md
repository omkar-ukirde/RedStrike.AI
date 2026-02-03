---
name: industrial-iot
description: Skills for attacking ICS/SCADA and industrial IoT protocols including Modbus, BACnet, and OPC-UA.
compatibility: Requires specialized ICS tools
allowed-tools: modbus-cli nmap pymodbus
metadata:
  category: network
---

# Industrial IoT / ICS

Industrial control system and building automation protocol exploitation.

## Skills

- [Modbus Pentesting](references/modbus-pentesting.md) - Modbus TCP (502)
- [BACnet Pentesting](references/bacnet-pentesting.md) - Building automation (47808/UDP)
- [EtherNet/IP](references/ethernetip-pentesting.md) - Industrial Ethernet (44818)
- [OPC-UA Pentesting](references/opcua-pentesting.md) - OPC Unified Architecture (4840)

## Quick Reference

| Protocol | Port | Sector |
|----------|------|--------|
| Modbus | 502 | Manufacturing, utilities |
| BACnet | 47808 | Building automation |
| EtherNet/IP | 44818 | Factory automation |
| OPC-UA | 4840 | Industrial automation |

> ⚠️ **Warning**: ICS/SCADA attacks can affect physical systems and safety.

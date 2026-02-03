---
name: vpn-tunneling
description: Skills for VPN exploitation and network tunneling techniques.
compatibility: Requires ike-scan, chisel, ligolo-ng
allowed-tools: ike-scan chisel ligolo-ng ssh
metadata:
  category: network
---

# VPN & Tunneling

VPN exploitation and post-exploitation tunneling.

## Skills

- [IPSec/IKE Pentesting](references/ipsec-ike-pentesting.md) - VPN attacks (500/4500)
- [Tunneling & Port Forwarding](references/tunneling-port-forwarding.md) - Pivoting techniques

## Quick Reference

| Technique | Tool | Use Case |
|-----------|------|----------|
| IKE PSK | ike-scan | VPN gateway attack |
| SSH Tunnel | ssh -L/-R/-D | Simple pivoting |
| Chisel | chisel | HTTP tunneling |
| Ligolo-ng | ligolo-ng | Full network access |

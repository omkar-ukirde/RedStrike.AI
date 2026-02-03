---
name: other-services
description: Skills for miscellaneous network services including Java RMI, X11, VoIP, and IPMI.
compatibility: Requires various specialized tools
allowed-tools: nmap metasploit
metadata:
  category: network
---

# Other Services

Miscellaneous network service exploitation.

## Skills

- [Java RMI Pentesting](references/java-rmi-pentesting.md) - RMI deserialization (1099)
- [X11 Pentesting](references/x11-pentesting.md) - X11 capture (6000+)
- [SIP/VoIP Pentesting](references/sip-voip-pentesting.md) - Voice attacks (5060)
- [IPMI Pentesting](references/ipmi-pentesting.md) - BMC attacks (623)
- [OMI Pentesting](references/omi-pentesting.md) - Azure OMIGOD (5986)

## Quick Reference

| Service | Port | Key Attack |
|---------|------|------------|
| Java RMI | 1099 | Deserialization RCE |
| X11 | 6000 | Screenshot, keylog |
| SIP | 5060 | Call interception |
| IPMI | 623 | Cipher 0, hash dump |
| OMI | 5986 | CVE-2021-38647 |

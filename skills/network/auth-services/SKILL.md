---
name: auth-services
description: Skills for attacking authentication and remote access services including SSH, RDP, Kerberos, and LDAP.
compatibility: Requires hydra, crackmapexec, impacket
allowed-tools: hydra crackmapexec impacket-scripts evil-winrm
metadata:
  category: network
---

# Authentication Services

Remote access and authentication service exploitation.

## Skills

- [SSH Pentesting](references/ssh-pentesting.md) - SSH security testing (22)
- [Telnet Pentesting](references/telnet-pentesting.md) - Telnet exploitation (23)
- [Kerberos Pentesting](references/kerberos-pentesting.md) - AD Kerberos attacks (88)
- [LDAP Pentesting](references/ldap-pentesting.md) - Directory enumeration (389/636)
- [RDP Pentesting](references/rdp-pentesting.md) - Remote Desktop attacks (3389)
- [VNC Pentesting](references/vnc-pentesting.md) - VNC security (5900+)
- [WinRM Pentesting](references/winrm-pentesting.md) - Windows remote mgmt (5985/5986)
- [R-Services](references/rlogin-rsh-rexec-pentesting.md) - Legacy Unix services (512-514)

## Quick Reference

| Service | Port | Key Attack |
|---------|------|------------|
| SSH | 22 | Brute force, key theft |
| Kerberos | 88 | AS-REP, Kerberoast |
| LDAP | 389 | Anonymous bind |
| RDP | 3389 | BlueKeep, brute force |

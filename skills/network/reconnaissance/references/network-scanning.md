# Network Scanning Skill

## Goal

Perform comprehensive network reconnaissance using Nmap and other scanning tools to discover hosts, open ports, running services, and potential vulnerabilities on a target network.

## Methodology

1. **Host Discovery**: Identify live hosts on the network using various ping techniques
2. **Port Scanning**: Discover open ports using TCP SYN, TCP Connect, UDP, or stealth scans
3. **Service Detection**: Identify services and versions running on open ports
4. **OS Fingerprinting**: Determine the operating system of target hosts
5. **Vulnerability Scanning**: Use NSE scripts to identify known vulnerabilities
6. **Output Analysis**: Parse and analyze scan results for actionable intelligence

## Tools

* **nmap**: The primary tool for network scanning and enumeration
* **masscan**: High-speed port scanner for large networks
* **rustscan**: Fast port scanner that integrates with nmap
* **netdiscover**: ARP reconnaissance tool for local networks
* **arp-scan**: ARP-based network scanner

## Example Commands

```bash
# Basic comprehensive scan
nmap -sV -sC -O -n -oA nmapscan 192.168.0.1/24

# Host discovery only (no port scan)
nmap -sn 192.168.0.0/24

# Fast scan of common ports
nmap -F -T4 192.168.0.1

# Full TCP port scan with service detection
nmap -sS -sV -p- -T4 192.168.0.1

# UDP scan for common services
nmap -sU -p53,67,68,69,123,161,162,500 192.168.0.1

# Aggressive scan with OS detection and scripts
nmap -A -T4 192.168.0.1

# Stealth scan (no ping, SYN scan)
nmap -Pn -sS -T2 192.168.0.1

# Vulnerability scanning with NSE
nmap --script vuln 192.168.0.1

# Scan specific ports
nmap -p 21,22,23,25,80,443,445,3389 192.168.0.1

# Output in all formats
nmap -sV -oA scan_results 192.168.0.1

# Scan with decoys for evasion
nmap -D RND:10 192.168.0.1

# Idle scan using zombie host
nmap -sI zombie_host 192.168.0.1

# High-speed scanning with masscan
masscan -p1-65535 192.168.0.0/24 --rate=10000

# ARP discovery on local network
netdiscover -i eth0 -r 192.168.0.0/24
arp-scan -l
```

## Scan Types Reference

| Scan Type | Flag | Description |
|-----------|------|-------------|
| SYN Scan | -sS | Stealthy, doesn't complete connection (default with root) |
| Connect Scan | -sT | Completes TCP handshake, leaves logs |
| UDP Scan | -sU | Scans UDP ports, slower |
| FIN Scan | -sF | Stealth scan, bypasses some firewalls |
| NULL Scan | -sN | No flags set, evades some firewalls |
| Xmas Scan | -sX | FIN, PSH, URG flags set |
| ACK Scan | -sA | Identifies filtered ports/firewalls |
| Window Scan | -sW | Determines open ports via TCP window |
| Idle Scan | -sI | Uses zombie host for anonymity |

## Timing Templates

| Template | Flag | Description |
|----------|------|-------------|
| Paranoid | -T0 | Very slow, IDS evasion |
| Sneaky | -T1 | Slow, IDS evasion |
| Polite | -T2 | Slower, less bandwidth |
| Normal | -T3 | Default |
| Aggressive | -T4 | Faster, reliable networks |
| Insane | -T5 | Very fast, may miss results |

## NSE Script Categories

```bash
# Authentication scripts
nmap --script auth 192.168.0.1

# Brute force scripts
nmap --script brute 192.168.0.1

# Discovery scripts
nmap --script discovery 192.168.0.1

# Exploit scripts
nmap --script exploit 192.168.0.1

# Vulnerability scripts
nmap --script vuln 192.168.0.1

# Safe scripts (won't crash services)
nmap --script safe 192.168.0.1
```

## Guidance for AI

* When the user asks for network reconnaissance, host discovery, or port scanning, activate this skill
* Always ask for the target IP range if not specified
* Recommend appropriate scan types based on the scenario:
  - Use -sS (SYN) for stealthy scans with root privileges
  - Use -sT (Connect) when root is not available
  - Use -sU for UDP services like DNS, SNMP, DHCP
* Warn about potential IDS/IPS detection for aggressive scans
* Suggest using -oA to save results in all formats for later analysis
* For large networks, recommend masscan for initial discovery, then nmap for detailed scans
* Always remind about authorization before scanning

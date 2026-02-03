# AD Enumeration Skill

## Goal

Enumerate Active Directory to map domain structure, identify attack paths, and find vulnerable configurations.

## Methodology

1. **Domain Discovery:** Identify domain controllers and domain info
2. **User Enumeration:** List users, groups, and attributes
3. **Computer Enumeration:** Map machines and their roles
4. **Trust Relationships:** Identify forest and domain trusts
5. **Attack Path Analysis:** Use BloodHound for visualization

## BloodHound Collection

### SharpHound (Windows)

```powershell
# Collect all data
.\SharpHound.exe -c All

# Specific collection methods
.\SharpHound.exe -c DCOnly
.\SharpHound.exe -c Session,LoggedOn

# Stealth mode
.\SharpHound.exe -c All --stealth
```

### BloodHound.py (Linux)

```bash
# Full collection
bloodhound-python -u user -p 'password' -d domain.local -ns <DC_IP> -c All

# Specific methods
bloodhound-python -u user -p 'password' -d domain.local -ns <DC_IP> -c Users,Groups,Computers
```

## LDAP Enumeration

### Linux

```bash
# Anonymous bind test
ldapsearch -x -H ldap://<DC_IP> -s base namingContexts

# Authenticated enumeration
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w 'password' -b "DC=domain,DC=local"

# Find users
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w 'password' \
  -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# Find domain admins
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w 'password' \
  -b "CN=Domain Admins,CN=Users,DC=domain,DC=local" member
```

### Windows (PowerView)

```powershell
# Domain info
Get-NetDomain
Get-NetForest
Get-DomainTrust

# Users
Get-DomainUser
Get-DomainUser -AdminCount
Get-DomainUser -PreauthNotRequired

# Groups
Get-DomainGroup -AdminCount
Get-DomainGroupMember "Domain Admins"

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained
```

## Key Queries

### High-Value Targets

```powershell
# Kerberoastable users
Get-DomainUser -SPN

# Unconstrained delegation
Get-DomainComputer -Unconstrained

# Constrained delegation
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# AdminCount users
Get-DomainUser -AdminCount
```

### ACL Analysis

```powershell
# Find ACLs for specific user
Get-ObjectAcl -SamAccountName <user> -ResolveGUIDs

# Find WriteDACL or GenericAll
Find-InterestingDomainAcl -ResolveGUIDs
```

## BloodHound Queries

Key pre-built queries:
- Shortest Path to Domain Admin
- Find Kerberoastable Users
- Find AS-REP Roastable Users
- Find Computers with Unconstrained Delegation
- Shortest Path to High Value Targets

## Tools

* **BloodHound** - Attack path visualization
* **SharpHound** - Windows data collector
* **bloodhound-python** - Python collector
* **PowerView** - PowerShell AD toolkit
* **ldapsearch** - LDAP CLI tool

## Guidance for AI

* Activate at start of AD engagements
* Run BloodHound collection first for visualization
* Check for Kerberoastable and AS-REP roastable users
* Look for unconstrained/constrained delegation
* Map privileged groups (Domain Admins, Enterprise Admins)
* Check trust relationships for cross-domain attacks

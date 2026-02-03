---
name: file-services
description: Skills for attacking file sharing services including FTP, SMB, NFS, and version control.
compatibility: Requires smbclient, nfs-common
allowed-tools: smbclient nfs-common ftp curl
metadata:
  category: network
---

# File Services

File sharing and transfer protocol exploitation.

## Skills

- [FTP Pentesting](references/ftp-pentesting.md) - FTP security (21)
- [TFTP Pentesting](references/tftp-pentesting.md) - TFTP exploitation (69)
- [NFS Pentesting](references/nfs-pentesting.md) - NFS shares (2049)
- [SMB Pentesting](references/smb-pentesting.md) - Windows shares (445/139)
- [Rsync Pentesting](references/rsync-pentesting.md) - Rsync access (873)
- [AFP Pentesting](references/afp-pentesting.md) - Apple Filing Protocol (548)
- [SVN Pentesting](references/svn-pentesting.md) - Subversion repos (3690)

## Quick Reference

| Service | Port | Key Check |
|---------|------|-----------|
| FTP | 21 | Anonymous login |
| SMB | 445 | Null session |
| NFS | 2049 | Exports list |
| Rsync | 873 | Module list |

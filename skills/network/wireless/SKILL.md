---
name: wireless
description: Skills for wireless network security testing including WiFi attacks.
compatibility: Requires aircrack-ng suite, wireless adapter
allowed-tools: aircrack-ng airmon-ng airodump-ng aireplay-ng
metadata:
  category: network
---

# Wireless Security

WiFi and wireless network exploitation.

## Skills

- [WiFi Pentesting](references/wifi-pentesting.md) - WPA/WPA2 attacks, evil twin

## Quick Reference

| Attack | Tool | Target |
|--------|------|--------|
| WPA Crack | aircrack-ng | 4-way handshake |
| Evil Twin | hostapd | Client capture |
| Deauth | aireplay-ng | Force reconnect |
| WPS | reaver | PIN brute force |

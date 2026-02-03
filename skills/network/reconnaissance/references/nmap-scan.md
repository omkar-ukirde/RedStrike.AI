# Nmap Scan Skill

## Goal

Perform a network scan using Nmap to discover hosts and services on a target network.

## Methodology

1.  **Identify the target:** Determine the IP range or hostname to scan.
2.  **Select scan type:** Choose the appropriate Nmap scan type (e.g., TCP SYN scan, UDP scan, version detection).
3.  **Execute the scan:** Run the Nmap command with the specified options.
4.  **Parse the output:** Analyze the Nmap output to identify open ports, running services, and potential vulnerabilities.

## Tools

*   **nmap:** The primary tool for network scanning.

## Example Command

```bash
nmap -sS -T4 -p- -A <target>
```

## Guidance for AI

*   When the user asks for a network scan, this skill should be activated.
*   Prompt the user for the target if it's not specified.
*   Use the methodology to guide the execution of the scan.
*   Summarize the findings from the Nmap output in a clear and concise way.

# Server-Side Request Forgery (SSRF) Skill

## Goal

Identify and exploit Server-Side Request Forgery (SSRF) vulnerabilities, where an attacker can induce a server-side application to make requests to an arbitrary domain.

## Methodology

1.  **Identify Potential SSRF:** Look for application functionality that makes requests to other services, such as fetching an image from a URL, calling a webhook, or querying a backend API.
2.  **Test Internal Network:** Try to make the server make requests to internal IP addresses (e.g., `127.0.0.1`, `169.254.169.254` for cloud metadata services, or other internal IPs).
3.  **Change Protocol:** Try to use different protocols, like `file://` to read local files, `gopher://` to send arbitrary data to other services, or `dict://` to interact with Redis servers.
4.  **Bypass Filters:** If there are filters in place, try to bypass them using techniques like using alternative IP address representations (e.g., decimal or octal), using a DNS record that points to an internal IP, or using redirects.

## Tools

*   **Burp Suite:** The primary tool for finding and exploiting SSRF.
*   **A collaborating server:** A server that you control to monitor for requests from the vulnerable application (e.g., Burp Collaborator or a simple netcat listener).

## Example Payload

```
https://example.com/getImage?url=http://127.0.0.1:8080/server-status
https://example.com/getImage?url=file:///etc/passwd
```

## Guidance for AI

*   When a user wants to test for SSRF, this skill should be activated.
*   Explain what SSRF is and the potential impact, including scanning internal networks and accessing sensitive data.
*   Guide the user on how to use a collaborating server to detect SSRF vulnerabilities.
*   Provide a list of common payloads for different protocols and cloud environments.
*   Explain how to use different IP address encodings to bypass filters.
*   Emphasize the high impact of this vulnerability and the need for careful testing.

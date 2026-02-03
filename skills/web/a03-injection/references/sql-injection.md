# SQL Injection Skill

## Goal

Identify and exploit SQL injection vulnerabilities in web applications.

## Methodology

1.  **Identify Injection Points:** Find user-controllable inputs that are likely to be used in SQL queries (e.g., URL parameters, form fields, HTTP headers).
2.  **Fuzzing:** Insert special characters (like `'`, `"`, `)`, `#`, `--`) into the inputs to see if they cause errors or changes in the application's behavior.
3.  **Confirm Vulnerability:** Use techniques like boolean-based, time-based, or error-based injection to confirm the vulnerability.
4.  **Extract Data:** Once the vulnerability is confirmed, use SQL injection payloads to extract data from the database.
5.  **Automated Scanning:** Use tools like `sqlmap` to automate the process of finding and exploiting SQL injection vulnerabilities.

## Tools

*   **Burp Suite:** To intercept and modify HTTP requests.
*   **sqlmap:** An automated tool for detecting and exploiting SQL injection flaws.
*   **A web browser's developer tools:** To inspect and modify form submissions and requests.

## Example Command (using sqlmap)

```bash
sqlmap -u "http://<target>/vulnerable_page.php?id=1" --dbs --batch
```

## Guidance for AI

*   When a user suspects an SQL injection vulnerability, this skill should be activated.
*   Guide the user on how to identify potential injection points.
*   Explain the different types of SQL injection (in-band, out-of-band, blind).
*   Provide example payloads for manual testing.
*   If the user wants to automate the process, guide them on how to use `sqlmap`.
*   Ask for the target URL and the parameter to test.
*   Warn the user about the potential to cause damage to the database and to only test on applications they have permission to test.

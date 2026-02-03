# Cross-Site Scripting (XSS) Skill

## Goal

Identify and demonstrate Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Methodology

1.  **Identify Input Vectors:** Find all points where user input is reflected back in the application's response (e.g., search bars, comment fields, profile information).
2.  **Test for Reflected XSS:** Inject simple HTML and JavaScript payloads (e.g., `<h1>test</h1>`, `<script>alert('XSS')</script>`) into the input vectors and see if they are executed by the browser.
3.  **Test for Stored XSS:** If the input is stored by the application (e.g., in a comment or a user profile), check if the payload is executed when the content is viewed by another user.
4.  **Test for DOM-based XSS:** Analyze the application's client-side JavaScript to see if it manipulates the DOM in an unsafe way with user-controllable data.
5.  **Bypass Filters:** If the application has XSS filters, try to bypass them using different encodings or more complex payloads.

## Tools

*   **A web browser:** The primary tool for testing XSS. The developer console is essential.
*   **Burp Suite:** To intercept and modify requests, and to automate some testing.
*   **XSS Hunter:** A tool to find stored XSS vulnerabilities.

## Example Payload

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert('XSS')>
```

## Guidance for AI

*   When a user wants to test for XSS, this skill should be activated.
*   Explain the difference between reflected, stored, and DOM-based XSS.
*   Provide a list of common XSS payloads for the user to try.
*   Guide the user on how to use their browser's developer tools to inspect the page and see if their payloads are being rendered.
*   If a vulnerability is found, explain the potential impact (e.g., session hijacking, keylogging).
*   Encourage responsible disclosure and testing only on authorized applications.

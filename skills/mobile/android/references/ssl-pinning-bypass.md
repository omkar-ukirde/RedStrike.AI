# SSL Pinning Bypass Skill

## Goal

Bypass SSL/TLS certificate pinning in Android applications to intercept HTTPS traffic.

## Methodology

1. **Identify Pinning:** Detect pinning implementation type
2. **Quick Bypasses:** Try automated bypass methods
3. **Frida Hooks:** Runtime certificate validation bypass
4. **APK Patching:** Static removal when runtime fails
5. **Traffic Capture:** Proxy with Burp/mitmproxy

## Detection Surface

Applications may implement:
- Custom TrustManager/HostnameVerifier
- OkHttp CertificatePinner
- Conscrypt pinning
- Native-level pinning
- Network Security Config pinning

## Quick Bypass Methods

### Step 1: Magisk DenyList (Root Detection)

```bash
# In Magisk:
# 1. Enable Zygisk
# 2. Enable DenyList
# 3. Add target package
# 4. Reboot
```

### Step 2: Frida Codeshare Scripts

```bash
# Common drop-in scripts
frida -U -f com.example.app -l anti-frida-detection.js
frida -U -f com.example.app -l ssl-bypass.js
```

### Step 3: Objection Universal Bypass

```bash
# Start objection
objection -g com.target.app explore

# Disable SSL pinning
android sslpinning disable

# Disable root detection
android root disable
```

## Frida SSL Bypass Hooks

### Universal SSL Bypass

```javascript
Java.perform(function(){
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var SSLContext = Java.use('javax.net.ssl.SSLContext');

  // No-op validations
  X509TrustManager.checkClientTrusted.implementation = function(){ };
  X509TrustManager.checkServerTrusted.implementation = function(){ };

  var TrustManagers = [ X509TrustManager.$new() ];
  var SSLContextInit = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;',
    '[Ljavax.net.ssl.TrustManager;',
    'java.security.SecureRandom'
  );
  SSLContextInit.implementation = function(km, tm, sr){
    return SSLContextInit.call(this, km, TrustManagers, sr);
  };
});
```

### OkHttp CertificatePinner Bypass

```javascript
Java.perform(function(){
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function(hostname, peerCertificates) {
        console.log('[+] Bypassing OkHttp pinning for: ' + hostname);
        return;
      };
  } catch(e) {}
});
```

## APK Patching (Static Bypass)

### Using apk-mitm

```bash
# Automatic certificate pinning removal
npx apk-mitm app.apk

# Install patched APK
adb install app-patched.apk
```

### Using Objection Patcher

```bash
# Inject Frida gadget into APK
objection patchapk --source app.apk

# Install patched APK
adb install app.objection.apk
```

## Proxy Setup

```bash
# Set device proxy
adb shell settings put global http_proxy <host>:<port>

# Start mitmproxy
mitmproxy -p 8080

# Or Burp Suite listening on all interfaces
```

## Medusa Framework

```bash
# Automated unpinning with Medusa
git clone https://github.com/Ch0pin/medusa
cd medusa
python medusa.py

# In Medusa console
use http_communications/multiple_unpinner
run com.target.app
```

## Root/Emulator Detection Bypass

```javascript
Java.perform(function(){
  var Build = Java.use('android.os.Build');
  Build.MODEL.value = 'Pixel 7 Pro';
  Build.MANUFACTURER.value = 'Google';
  Build.FINGERPRINT.value = 'google/panther/panther:14/UP1A:user/release-keys';

  var Debug = Java.use('android.os.Debug');
  Debug.isDebuggerConnected.implementation = function() { return false; };
});
```

## Tools

* **Frida** - Dynamic instrumentation
* **Objection** - Frida wrapper with helpers
* **apk-mitm** - Automatic pinning removal
* **Medusa** - Frida automation framework
* **Magisk** - Root and DenyList

## Guidance for AI

* Activate when intercepting Android HTTPS traffic fails
* Try Objection's sslpinning disable first (quickest)
* Use apk-mitm for static patching if runtime fails
* Frida hooks work for most Java-based pinning
* Native pinning requires more advanced techniques
* Consider root detection bypass alongside SSL bypass

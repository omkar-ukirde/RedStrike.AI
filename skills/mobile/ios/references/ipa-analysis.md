# iOS IPA Analysis Skill

## Goal

Perform static and dynamic analysis of iOS applications to identify vulnerabilities.

## Methodology

1. **Extract IPA:** Unpack and analyze application bundle
2. **Static Analysis:** Review binary, plist, and entitlements
3. **Data Storage:** Check for insecure data storage
4. **Dynamic Analysis:** Runtime testing with Frida/Objection
5. **Network:** Certificate pinning bypass and traffic interception

## Static Analysis

### Extract IPA

```bash
# Unzip IPA file
unzip app.ipa -d app_extracted

# App bundle location
ls app_extracted/Payload/*.app/
```

### Analyze Info.plist

```bash
# View Info.plist
plutil -p app_extracted/Payload/*.app/Info.plist

# Check for:
# - NSAppTransportSecurity exceptions
# - URL Schemes (CFBundleURLSchemes)
# - Purpose strings (Privacy - *)
# - UIRequiredDeviceCapabilities
```

### Binary Analysis

```bash
# Check architecture
lipo -info binary

# Get Objective-C classes
class-dump binary > classes.h

# Check for PIE and stack protection
otool -hv binary

# Strings analysis
strings binary | grep -i password
strings binary | grep -i api
```

### Entitlements

```bash
# Extract entitlements
codesign -d --entitlements :- app.app

# Check for dangerous entitlements:
# - get-task-allow (debugging)
# - application-identifier
# - keychain-access-groups
```

## Data Storage Analysis

### Locations to Check

```bash
# App data directory (jailbroken device)
/var/mobile/Containers/Data/Application/[uuid]/

# Key locations:
Documents/        # User data
Library/          # App settings
Library/Caches/   # Cache data
tmp/              # Temporary files
```

### Plist Files

```bash
# Check for sensitive data in plists
find . -name "*.plist" -exec plutil -p {} \;
```

### SQLite Databases

```bash
# Find and examine databases
find . -name "*.db" -o -name "*.sqlite"
sqlite3 database.db ".dump"
```

### Keychain

```bash
# On jailbroken device, use keychain-dumper
./keychain-dumper

# Check for:
# - Passwords stored insecurely
# - kSecAttrAccessibleAlways items
# - Data that persists after app deletion
```

## Dynamic Analysis

### Frida Setup

```bash
# Start Frida server on device
frida-server &

# List apps
frida-ps -Ua

# Attach to app
frida -U -n "AppName"
```

### Objection

```bash
# Start Objection
objection -g com.target.app explore

# Common commands
ios info binary
ios plist cat Info.plist
ios keychain dump
ios nsurlcredentialstorage dump
ios cookies get
ios sslpinning disable
```

### Local Authentication Bypass

```javascript
// Bypass LAContext (TouchID/FaceID)
Java.perform(function(){
  var LAContext = ObjC.classes.LAContext;
  LAContext['- evaluatePolicy:localizedReason:reply:'].implementation = function(policy, reason, reply) {
    var callback = new ObjC.Block(reply);
    callback.implementation(true, null);
  };
});
```

## Network Analysis

### Certificate Pinning Bypass

```bash
# Using Objection
objection -g com.target.app explore
ios sslpinning disable

# Using Frida script
frida -U -f com.target.app -l ios-ssl-bypass.js
```

### Proxy Setup

```bash
# Configure proxy in iOS Settings
# Settings > Wi-Fi > [network] > Configure Proxy > Manual

# Install Burp CA certificate
# Settings > General > VPN & Device Management > Install Profile
```

## Vulnerability Checks

### URL Schemes

```bash
# Test deep links
# Look for exported URL schemes in Info.plist

xcrun simctl openurl booted "appscheme://test"
```

### WebViews

```bash
# Check for:
# - javaScriptEnabled
# - allowFileAccessFromFileURLs
# - WKWebView vs UIWebView
```

### Binary Protections

```bash
# Check for:
# - PIE enabled
# - Stack canaries
# - ARC enabled
```

## Tools

* **class-dump** - Objective-C header extraction
* **otool** - Binary analysis
* **Frida** - Dynamic instrumentation
* **Objection** - Frida-based exploitation
* **keychain-dumper** - Keychain extraction

## Guidance for AI

* Activate for iOS app testing engagements
* Requires jailbroken device for full testing
* Check Info.plist for URL schemes and permissions
* Keychain data persists after app deletion (security risk)
* Test both data storage and network security
* Local authentication (biometrics) is often bypassable

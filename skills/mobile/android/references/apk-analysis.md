# Android APK Analysis Skill

## Goal

Perform static and dynamic analysis of Android applications to identify vulnerabilities.

## Methodology

1. **Extract APK:** Decompile and analyze application package
2. **Static Analysis:** Review code, manifest, and configurations
3. **Dynamic Analysis:** Runtime testing with instrumentation
4. **Data Storage:** Check for insecure data storage
5. **Network:** Intercept and analyze traffic

## Static Analysis

### Extract and Decompile

```bash
# Using apktool
apktool d app.apk -o app_extracted

# Using jadx for Java source
jadx -d output app.apk

# Using MobSF for automated scan
# Web interface at http://localhost:8000
```

### Analyze Manifest

```bash
# Check AndroidManifest.xml for:
# - Exported Activities, Services, Receivers
# - android:debuggable="true"
# - android:allowBackup="true"
# - URL Schemes and Intent Filters
# - Permissions

# android:exported mandatory on Android 12+
# Misconfigured exports lead to external intent invocation
```

### Search for Secrets

```bash
# Look for hardcoded credentials
grep -ri "password" app_extracted/
grep -ri "api_key" app_extracted/
grep -ri "secret" app_extracted/

# Firebase URLs
grep -ri "firebaseio.com" app_extracted/

# Search in strings
strings classes.dex | grep -i token
```

### Code Review Keywords

```bash
# In jadx, search for:
# - SharedPreferences (insecure storage)
# - SQLiteDatabase (unencrypted data)
# - WebView.addJavascriptInterface (RCE risk)
# - MODE_WORLD_READABLE/WRITEABLE
# - getExternalStorage (world-readable)
```

## Dynamic Analysis

### Environment Setup

```bash
# Using Android Virtual Device
emulator -avd <avd_name> -writable-system

# Or physical device with root/Magisk
adb devices
```

### Frida Setup

```bash
# Push frida-server to device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# List running apps
frida-ps -Ua
```

### Runtime Analysis

```bash
# Attach with Objection
objection -g com.target.app explore

# Common Objection commands
android hooking list classes
android hooking list activities
android sslpinning disable
android root disable
```

### Data Storage Checks

```bash
# Check app data directory
adb shell run-as com.target.app ls -la /data/data/com.target.app/

# SQLite databases
adb shell run-as com.target.app cat databases/*.db

# SharedPreferences
adb shell run-as com.target.app cat shared_prefs/*.xml
```

## Vulnerability Checks

### Exported Components

```bash
# List exported activities
adb shell dumpsys package com.target.app | grep -A 5 "exported=true"

# Call exported activity
adb shell am start -n com.target.app/.ExportedActivity
```

### WebView Vulnerabilities

```javascript
// Check for addJavascriptInterface
// Check javaScriptEnabled
// Check allowFileAccessFromFileURLs
```

### Intent Injection

```bash
# Test deep links
adb shell am start -a android.intent.action.VIEW -d "scheme://host/path"
```

## Tools

* **jadx** - APK decompiler
* **apktool** - APK extraction
* **MobSF** - Automated analysis
* **Frida** - Dynamic instrumentation
* **Objection** - Frida-based exploitation

## Guidance for AI

* Activate for Android app testing engagements
* Check manifest for exported components first
* Look for hardcoded secrets in strings and code
* Use MobSF for quick automated scan
* Dynamic testing requires rooted device or emulator
* Check both internal and external storage for sensitive data

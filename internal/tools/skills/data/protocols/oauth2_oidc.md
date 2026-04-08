---
name: oauth2-oidc
description: Full OAuth 2.0 and OpenID Connect flow testing including PKCE bypass, token exchange abuse, and cross-client attacks
---

# OAuth 2.0 / OIDC Protocol Testing

## Flow-Specific Attacks

### Authorization Code Flow

```bash
# Test redirect_uri validation
# See skills/vulnerabilities/oauth2_attacks.md for comprehensive redirect_uri bypass techniques

# Test code reuse — exchange same code twice
curl -sk "https://TARGET/token" -X POST -d "code=AUTH_CODE&grant_type=authorization_code&client_id=ID&redirect_uri=URI"
# Wait, then replay the same request — if token returned → code reuse vulnerability
```

### PKCE Flow

```bash
# Test PKCE downgrade — omit code_challenge in authorize, omit code_verifier in token
# Test plain vs S256 — server should enforce S256 only
curl -sk "https://TARGET/authorize?response_type=code&client_id=ID&redirect_uri=URI&code_challenge_method=plain&code_challenge=XXXX"
```

### Device Authorization Flow

```bash
# Test for unrestricted polling
curl -sk "https://TARGET/device/code" -X POST -d "client_id=ID&scope=openid"
# If device code returned → test brute-force of user_code (usually 8 chars)
```

### Token Introspection

```bash
# Test if introspection endpoint is publicly accessible
curl -sk "https://TARGET/introspect" -X POST -d "token=ACCESS_TOKEN"
# If active=true with user info → information disclosure
```

## Pro Tips

1. Always map the full OAuth flow before attacking — understand which grant types are supported
2. Test ALL grant types: authorization_code, implicit, client_credentials, device_code, refresh_token
3. PKCE is mandatory for public clients — verify it can't be downgraded to plain or omitted
4. Token introspection and revocation endpoints often lack proper authorization
5. Test cross-client token usage — token from Client A used against Client B's resources

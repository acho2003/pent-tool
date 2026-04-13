---
name: broken-function-level-authorization
description: BFLA testing for action-level authorization failures across endpoints, admin functions, and API operations
---

# Broken Function Level Authorization (BFLA)

BFLA is action-level authorization failure: callers invoke functions (endpoints, mutations, admin tools) they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject × action at the service that performs the action.

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust X-User-Id/X-Role injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides

## Reconnaissance

### Surface Enumeration

- Admin/staff consoles and APIs, support tools, internal-only endpoints exposed via gateway
- Hidden buttons and disabled UI paths (feature-flagged) mapped to still-live endpoints
- GraphQL schemas: mutations and admin-only fields/types; gRPC service descriptors (reflection)
- Mobile clients often reveal extra endpoints/roles in app bundles or network logs

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change

## Key Vulnerabilities

### Verb Drift and Aliases

- Alternate methods: GET performing state change; POST vs PUT vs PATCH differences; X-HTTP-Method-Override/_method
- Alternate endpoints performing the same action with weaker checks (legacy vs v2, mobile vs web)

### Edge vs Core Mismatch

- Edge blocks an action but core service RPC accepts it directly; call internal service via exposed API route or SSRF
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence

### Feature Flag Bypass

- Client-checked feature gates; call backend endpoints directly
- Admin-only mutations exposed but hidden in UI; invoke via GraphQL or gRPC tools

### Batch Job Paths

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller

### Content-Type Paths

- JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser

## Advanced Techniques

### GraphQL

- Resolver-level checks per mutation/field; do not assume top-level auth covers nested mutations or admin fields
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms

```graphql
mutation Promote($id:ID!){
  a: updateUser(id:$id, role: ADMIN){ id role }
}
```

### gRPC

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role
- Reflection lists services/methods; call admin methods that the gateway hid

### WebSocket

- Handshake-only auth: ensure per-message authorization on privileged events (e.g., admin:impersonate)
- Try emitting privileged actions after joining standard channels

### Multi-Tenant

- Actions requiring tenant admin enforced only by header/subdomain; attempt cross-tenant admin actions by switching selectors with same token

### Microservices

- Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz

## Bypass Techniques

### Header Trust

- Supply X-User-Id/X-Role/X-Organization headers; remove or contradict token claims; observe which source wins

### Route Shadowing

- Legacy/alternate routes (e.g., /admin/v1 vs /v2/admin) that skip new middleware chains

### Idempotency and Retries

- Retry or replay finalize/approve endpoints that apply state without checking actor on each call

### Cache Key Confusion

- Cached authorization decisions at edge leading to cross-user reuse; test with Vary and session swaps

### X-Original-URL / X-Rewrite-URL Bypass (Practitioner Critical)

Front-end path-based restrictions can be bypassed when the backend honors override headers:

```bash
# Front-end blocks /admin but backend reads X-Original-URL
curl -sk "https://TARGET/" -H "X-Original-URL: /admin" -H "Cookie: session=$SESSION"
curl -sk "https://TARGET/?username=carlos" -H "X-Original-URL: /admin/delete" -H "Cookie: session=$SESSION"

# X-Rewrite-URL variant (IIS/Apache)
curl -sk "https://TARGET/" -H "X-Rewrite-URL: /admin/panel" -H "Cookie: session=$SESSION"

# URL path override via request line
# GET / HTTP/1.1 with X-Original-URL: /admin → bypasses URL-based ACL
```

### Method-Based Access Control Bypass (Practitioner Critical)

Admin action restricted to POST but accessible via other HTTP methods:

```bash
# Original admin action (POST restricted to admin)
curl -sk "https://TARGET/admin-roles" -X POST \
  -d "username=wiener&action=upgrade" -H "Cookie: session=$USER_SESSION"
# → 403 Forbidden

# Try alternative methods
curl -sk "https://TARGET/admin-roles?username=wiener&action=upgrade" -X GET \
  -H "Cookie: session=$USER_SESSION"
# → 200 OK (method not checked!)

# Try POSTX, HEAD, OPTIONS
curl -sk "https://TARGET/admin-roles" -X POSTX \
  -d "username=wiener&action=upgrade" -H "Cookie: session=$USER_SESSION"

# Method override
curl -sk "https://TARGET/admin-roles" -X POST \
  -H "X-HTTP-Method-Override: GET" \
  -d "username=wiener&action=upgrade" -H "Cookie: session=$USER_SESSION"
```

### Referer-Based Access Control Bypass (Practitioner Critical)

Some admin sub-pages only check if the Referer header contains the admin URL:

```bash
# Admin panel at /admin → requires admin role ✓
# Admin sub-pages check Referer instead of session role
curl -sk "https://TARGET/admin-roles?username=wiener&action=upgrade" \
  -H "Referer: https://TARGET/admin" \
  -H "Cookie: session=$NON_ADMIN_SESSION"
# If the server checks Referer: /admin instead of actual role → bypass
```

### URL Matching Inconsistencies

```bash
# Case sensitivity bypass
curl -sk "https://TARGET/ADMIN" -H "Cookie: session=$SESSION"
curl -sk "https://TARGET/Admin" -H "Cookie: session=$SESSION"

# Trailing slash
curl -sk "https://TARGET/admin/" -H "Cookie: session=$SESSION"

# Path traversal in URL
curl -sk "https://TARGET/public/../admin" -H "Cookie: session=$SESSION"

# Semicolon path parameter
curl -sk "https://TARGET/admin;.css" -H "Cookie: session=$SESSION"
```

## Testing Methodology

1. **Build Actor × Action matrix** - Unauth, basic, premium, staff/admin; enumerate actions per role
2. **Obtain tokens/sessions** - For each role
3. **Exercise every action** - Across all transports and encodings (JSON, form, multipart), including method overrides
4. **Vary headers and selectors** - Org/tenant/project; test behind gateway vs direct-to-service
5. **Include background flows** - Job creation/finalization, webhooks, queues; confirm re-validation

## Validation

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented
- Feature toggles intentionally open to all roles for preview/beta with clear policy
- Simulated environments where admin endpoints are stubbed with no side effects

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings
3. Inspect gateways for identity header injection; never trust client-provided identity
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor
5. Prefer minimal PoCs: one request that flips a privileged field or invokes an admin method with a basic token

## Summary

Authorization must bind the actor to the specific action at the service boundary on every request and message. UI gates, gateways, or prior steps do not substitute for function-level checks.

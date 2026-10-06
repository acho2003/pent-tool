# Unified web/API and network workflow

The expanded workflow is opt-in: `XALGORIX_UNIFIED_WORKFLOW=1`.
It remains disabled in Compose by default until isolated runtime acceptance is
complete. The execution/authentication corrections and truthful result outcomes
also apply to existing typed assessments without enabling expanded discovery.

## Approval and recovery

Discovery never authorizes another hostname, port, scheme, or path. Candidates
appear in Scan Details → Recorded coverage. Select destinations, approve the
preview, review the generated jobs, then start the approved revision.

`GET /api/scans/{id}/discovery` returns candidate provenance and the fingerprint.
`POST` on the same route accepts `fingerprint` and `selected_ids`. Stale previews
return 409. Accepted revisions live under `revisions/` in the parent assessment
and reload after a browser/server restart. Revised assessments retain the parent
assessment ID, parent plan fingerprint, and approval preview fingerprint. Start
rejects revisions without their matching persisted approval. New targets do not
inherit target credentials.

Existing accepted jobs finish before a revised plan starts. A pending expansion
is not lost because the original assessment has finished: its candidate evidence
and approval remain available in saved artifacts.

## Evidence and coverage

Inventory schema 2 preserves encoded paths, trailing slashes, repeated query
parameters, query-value variants, methods, parameter schemas, body digests, and
authentication observations. Grouping identity is distinct from request identity.
Old snapshots and findings remain readable; missing provenance stays unknown.

Each attempt writes `input-manifest.json`. Scoped recording writes append-only
`coverage-events.jsonl`; endpoint IDs join the files to inventory and attempt
history. `GET /api/scans/{id}/endpoints/{endpoint_id}/trace` supports `page`, `size`,
`scanner`, and `attempt_id` filters. The endpoint trace in Scan Details exposes
that evidence without guessing that a completed batch exercised each URL.
`GET /api/scans/{id}/coverage/items` supports paginated `metric` and `scanner`
filters. Every displayed count links to its inventory/evidence members.
Inventory scope is persisted separately from scanner execution scope.

Coverage and reports use the same proof calculation. Distinguish selected,
submitted, acknowledged, observed active endpoints, batch completed, failed,
skipped, and unknown. Seeding traffic does not count as active testing. Parameter
checks, executed template counts, and protected-route coverage remain NOT TRACKED
unless an adapter provides the corresponding proof. Report generation is offline.

Run outcomes separate execution, parsing, authentication, and completeness.
Malformed/missing reports cannot be successful zero-finding scans. JSON/JSONL
limits preserve complete records. Valid sealed partial artifacts can contribute
findings, labelled partial, after timeout or cancellation.

## Runtime configuration

Keep the managed ZAP daemon dedicated. Its pinned Compose image contains network
0.28.0, OpenAPI 56.0.0, and GraphQL 0.33.0 in the inspected runtime. Expanded ZAP
execution refuses unavailable network proxy configuration or an already enabled
upstream proxy. All three tested add-on versions are checked before expanded
execution. Proxy restoration failure quarantines the daemon. Compose enables
key-protected API file transfer for filtered schema imports. OpenAPI imports
contain approved, resolved operations without invented parameter values.
GraphQL imports contain materialized read queries; mutation/subscription roots
and unresolved queries are removed, and native query generation is disabled
while importing. Exact methods and query-value variants are seeded separately.

`XALGORIX_SCANNER_GATEWAY_HOST=xalgorix` advertises the application container to
ZAP. The gateway binds ephemeral internal ports and authenticates each attempt;
these ports are not published to the host. Local CLI-only runs can leave this
variable unset to bind loopback. HTTPS CONNECT is terminated using an ephemeral
attempt CA so scope and method exclusions apply inside TLS. Upstream certificate
validation remains enabled. Target credentials are injected only for their bound
origin, and proxy credentials never reach targets.

Browser discovery uses the existing Chromium through Go/Rod. It records scoped
HTTP navigations, JavaScript requests, and form definitions. It does not submit
forms automatically. Request, response-size, navigation, and time limits are
reported as discovery gaps.

Wapiti GET-input routing uses batches of 50 under one overall time budget rather
than silently dropping the remaining endpoints. State-changing API operations
continue through the existing explicitly approved fixture/cleanup adapter. URL-only
adapters refuse HEAD variants rather than converting them to GET; ZAP preserves
HEAD and the encoded absolute request URI. Nuclei uses its native offline listing
to save `template-inventory.json`; enabled templates are separate from proven
executed checks.
Unsupported request bodies/methods must remain visible coverage gaps; never
reinterpret the single-write approvals as permission for repeated fuzzing.

## Validation and deployment

Run `CGO_ENABLED=0 go test ./...`, `npm --prefix webui run typecheck`, and
`npm --prefix webui run build`. The fixture suite includes 684 request identities,
batching beyond 50 inputs, scope boundaries, auth forwarding, HTTP/TLS recording,
schema validation, redaction, partial evidence, and legacy compatibility.

Build a native arm64 validation image using a temporary tag, and run the offline
runtime smoke test. Existing Docker CI validates amd64 before publication. Both
Docker build paths accept `VCS_REF` for the OCI revision label; new scanner runs
also record their Go VCS build revision. The full Docker build injects VCS_REF
into the binary when its build context has no Git metadata.

Do not replace the application image or enable the expanded flag until runtime
acceptance passes. Recreate only the application container when deploying. Keep
existing data volumes, credentials, Greenbone feeds, service images, and lab
images. No global pruning is part of this workflow.

Native fixture checks are opt-in Go tests. Build the scanner test binary for
Linux arm64 and run it in the retained runtime with `XALGORIX_TEST_CHROMIUM`,
`XALGORIX_TEST_NUCLEI_NATIVE`, and `XALGORIX_TEST_ZAP`. ZAP must be a disposable,
dedicated daemon on an isolated internal Docker network. Optional
`XALGORIX_TEST_GMP_SOCKET` sends only `<get_version/>` to an existing Greenbone
socket. These checks do not scan public targets.

Expanded acceptance is not complete merely because these adapter fixtures pass.
Wapiti POST fuzzing, browser storage access, the complete staged/restart workflow,
and the full 684-request execution fixture still need acceptance before enabling
the expanded workflow by default.

New web/API/network plans accepted while rollout is enabled carry `workflow_version: unified-v1`. Saved plans without that marker retain the legacy executor, even if rollout is later enabled. Expanded plans cannot execute while the flag is disabled. Coverage uses the persisted inventory version rather than the current server flag.

Wapiti selection uses the configured assessment endpoint budget for expanded plans and splits the selected inputs into batches of 50. A deterministic assessment fixture routes 684 query inputs through 14 batches and checks distinct submission records; it does not claim that a native scanner exercised all 684 requests.

Chromium discovery can observe a single explicit read-only GraphQL JSON POST, including named operations and supplied variables. It refuses mutations, subscriptions, mixed read/write documents, batch requests and opaque persisted queries. Captured variants retain SHA-256 digests and parameter names in public evidence. Exact URLs, headers and bodies are encrypted with the existing credential key in a scope/authentication-bound replay store. ZAP restores captured read-only GraphQL POST bodies; missing or incompatible replay remains explicitly unavailable. The gateway accepts only the captured read-only body and blocks mutations and uncaptured variants. Browser limit reasons identify the exhausted request, navigation queue, depth, response-size or time budget.

Discovery previews list the active DNS, HTTP and configured network preparation actions for each candidate, and those actions contribute to the preview fingerprint. Approved child-plan destinations keep DNS/HTTP preparation jobs even when custom vulnerability scanner selection omits them. Missing prerequisite executables remain explicit unavailable jobs; original targets and legacy plans are not upgraded. Same-origin paths outside an accepted path boundary remain approval candidates.

Target access supports encrypted optional `localStorage` and `sessionStorage` string maps alongside an HTTP header/cookie or form credential. They are initialized before navigation only on that credential’s original origin. Storage-bound browser requests cannot transfer to aliases. Select **Verify in Chromium**, provide a protected-route marker, and use **Test access** to run the same worker before planning. The setting is persisted in the accepted plan, repeated before execution and checked periodically. Verification requires both an authenticated marker and an anonymous negative control; access testing does not crawl links or submit forms. HTTP scanners still require their explicit header/cookie credentials; browser storage does not automatically become a scanner bearer token.

Replay files are immutable authenticated envelopes under each scan’s private `request-replay` directory. Inventory snapshots and scanner input manifests expose references, never replay headers or bodies. Sensitive supplied URL seeds also require encrypted replay. Browser-derived credentials augment output redaction. Reporting remains offline and does not decrypt request replay.

Structured ZAP assessments seed exclusively from their saved input manifest. They do not independently pre-seed a root or duplicate API operations. API operation results reference the corresponding submission disposition; filtered schema imports contain selected operations only. The native 684-request fixture verifies saved seeding receipts, including exact read-only HTTPS POST bodies, without claiming active-check completion.

Expanded request budgets count selected method/body variants individually, even when they share a URL. Browser form definitions require operation approval and supplied inputs before submission; they do not authorize a GET request by themselves. DOM alias observations do not inherit authentication. Redacted discovery URLs without their bound replay reference remain unmaterialized. Classifier version 6 invalidates cached eligibility from previous rules without contacting targets.

Expanded approved API writes use an assessment-wide journal, shared across attempts and protected by an OS process lock. Every transition reloads disk state and syncs the file and containing directories before network execution. Saved per-attempt intents are imported without inventing outcomes; corrupt or unresolved journals prevent automatic resume. Discovery approval clears prior write approvals, so accepting new destinations cannot renew mutation consent. Unsupported locking platforms refuse writes.


Registry version 10 includes separate scanner jobs for additional named target
identities in the accepted preview. Nuclei, ZAP, Wapiti and Dalfox select only
that identity's browser observations and resolved same-origin read-operation
schema seeds. Each job renews its own target-bound credential; an unavailable
role never substitutes the primary credential. Execution receipts attach only
to the matching identity's exact request variants. Role jobs are labelled in
setup and revision review. This does not authorize repeated state-changing
fuzzing or extend credential bindings to aliases.

The derived workflow manifest is checkpointed after every job. A stage with
pending jobs remains running, and partial evidence remains partial. Persistence
failure stops later execution. Restart reuses only completed attempts with the
accepted plan fingerprint and valid saved checksums; interrupted attempts receive
new IDs. Authentication is reverified during resumed work.

Saved native JSON, JSONL, XML and text artifacts are sanitized for configured and
common unknown credentials before public download. Structured decoding preserves
record boundaries and native IDs; malformed structured artifacts cannot count as
usable success. Native scanners initially write private raw artifacts, so this
is not a claim of sanitization before every filesystem write.


Registry version 11 runs bounded supplemental ZAP discovery during inventory
preparation when ZAP is selected. Forms and POST-form processing are disabled,
spider depth matches Katana's depth of five, one spider thread is used, and the
pass is capped at five minutes and the existing endpoint/request budgets. The
scope gateway also enforces exclusions and approved path/origin boundaries.
Daemon settings, credentials and proxy configuration are restored under its
exclusive lease; failed restoration quarantines the service.

Only saved gateway response observations become live endpoint evidence. Blocked
or failed requests remain candidate dispositions. The resulting shared inventory
is sealed before the selected vulnerability scanners receive their manifests.
Supplemental discovery does not run active vulnerability checks. ZAP's later
active scan continues to seed only selected inventory requests without another
independent spider. Credential renewal now updates the gateway injection value
alongside the scoped ZAP rule.

## Bounded approved form campaigns

Expanded assessments can separately configure `fuzz_approvals` for Wapiti POST
campaigns. This consent does not change exactly-once `write_approvals`. Each
approval names the target, matching supplied OpenAPI operation, URL-encoded
fixture reference, exact DELETE cleanup path, scanner `wapiti`, request limit
(1–1000), and `repeat_testing_approved: true`. A non-Black-Box declared test
environment is required. The dashboard exposes these controls under Access &
inputs. Credentials remain bound to the default target identity; approval does
not authorize campaigns under additional identities.

Installed Wapiti 3.3.2 loses repeated form keys and double-encodes pre-encoded
values. Its supported fixtures therefore contain at most 64 unique fields,
64 KiB total, with plain ASCII letters, digits, dots, underscores, tildes and
hyphens. Incompatible fixtures are rejected during preview and execution;
JSON, multipart, repeated and encoded inputs remain explicit adapter gaps.
They are not silently converted or automatically approved for another scanner.

The recording gateway admits only the exact operation, approved field names
and multiplicities, URL-encoded content type, and bounded POST count. GET/HEAD
support traffic is restricted to the same entry URL. The campaign intent is
journaled before opening the gateway, and restart cannot replay the consent or
reset its budget. On completion or cancellation, admitted POST traffic drains
before separately scoped, bounded cleanup. Failed cleanup or uncertain request
evidence leaves the journal unresolved. A successful scanner process without
an observed POST is reported as partial rather than a clean campaign. Native
request observations prove traffic, not that every vulnerability check ran.

Registry version 12 records this planning and execution policy. The expanded
workflow remains disabled by default pending complete rollout acceptance.

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

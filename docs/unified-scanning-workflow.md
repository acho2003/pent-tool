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
Staged end-to-end suites (`runtime/staged-acceptance.sh`) now run real assessments
through the server, the dashboard in a real browser, two identities, definition
imports, Nuclei, Wapiti with an approved form campaign, Dalfox, ZAP, injected
failures and hard-kill restarts; their outcomes are recorded in
[unified-workflow-validation.md](unified-workflow-validation.md). What still blocks
enabling the expanded workflow by default is an actual amd64 validation run, a
final rollout review, and the boundary limitations listed there (adapters that run
outside the recording gateway, and credentials visible on child command lines).

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

## Schemathesis API fuzzing

Registry version 29 adds Schemathesis 4.32.5 as an optional web/API adapter for
unified-v1 plans. The planner selects it automatically only for a target with a
bound API definition; without one it stays optional, and a custom scanner
selection that omits it is respected. Named identities get their own jobs, like
Nuclei, ZAP, Wapiti and Dalfox.

Schemathesis never receives the operator's original document. Each attempt
rebuilds an OpenAPI 3.0 definition from the plan's operations and keeps only
OpenAPI GET/HEAD operations without a required body whose paths stay under the
approved application URL, inside the approved scope and outside its exclusions.
Every other operation is recorded as skipped with its reason in
`scanner-output/schemathesis/operations.json`, and any skipped operation leaves
the run's coverage partial. Path and query parameters keep their declared types
and use operator-supplied values as examples; header and cookie parameters are
not generated. GraphQL operations are skipped because generated GraphQL input
is sent as POST bodies the read-only gateway policy does not admit.

The run passes only through the recording gateway (it is not applicable
without one). The gateway injects and renews the verified session, so no
credential is placed on the Schemathesis command line; it also enforces scope,
exclusions, GET/HEAD/OPTIONS and the request budget, and records every request.
The base URL is the approved application URL, so Schemathesis's own capability
probes stay inside the boundary. A configuration file disables the coverage
phase's "unspecified HTTP method" cases, which otherwise send TRACE, QUERY and
write methods to declared paths. The stateful phase is off, one worker runs at
the profile rate, redirects are not followed and no example database persists.

Only the `not_a_server_error` check runs. The rebuilt definition has no
response schemas, so conformance checks would judge invented contracts, and
`ignored_auth` would mistake the gateway's re-injected session for an
authentication bypass. A 5xx response the target itself returned becomes a
low-severity CWE-755 finding with the request, status and response excerpt;
responses the gateway produced (marked `X-Xalgorix-Gateway-Rejection`, which
the gateway strips from upstream responses) are discarded. Exit code 1 means
failures or errors, so the NDJSON event log decides: a fatal error fails the
run, while a missing end event, an early stop or errored test cases make it
partial. Response bodies are stored base64-encoded; the artifact sanitizer now
decodes `$base64` values to redact secrets a target echoes back.

Schemathesis coverage is per operation, not per recorded request: inventory
endpoints carry an explicit "tests OpenAPI operations" reason rather than a
submission claim, and gateway events show the requests actually sent.

## Identity access matrix (Autorize-style)

The Autorize Burp extension needs an interactive Burp session, so it cannot run
inside automated assessments. Registry version 30 adds `authz-matrix`, a native
check with the same idea. It is optional and selected automatically for
unified-v1 targets with two or more bound identities; it is not split into
per-identity jobs because it compares identities itself.

It replays GET requests that a verified identity actually observed while
browsing (not seeds, schema operations or HEAD), skipping routes whose names
suggest a state change, at most 100 per attempt. Each request is sent again as
its owner (a fresh baseline), anonymously, and as every other verified identity,
each with only its own renewed credential, through the same scoped client and
budget as the native API checks. Bodies are compared after removing CSRF tokens,
nonces, timestamps and long opaque tokens.

Autorize reports every equal response as a bypass, which floods results with
shared and public pages. Here a `bypass_suspected` row and its tentative
CWE-285 finding need all of: a 2xx owner baseline of at least 64 bytes, a denied
anonymous control (401/403/404 or a redirect away), an equivalent response for
the other identity, and that identity's own browsing never reaching the request.
Other rows are `enforced`, `denied` (anonymous), `shared`, `public`,
`different_response`, `equivalent_unprotected_unknown` or `unknown`, each with a
reason. Sessions are verified again after the matrix; rows for an identity that
lost its session become unknown and its findings are withheld, and a stopped
matrix withholds all suspected bypasses. Results appear as `access_matrix` in
coverage, the scan detail page and the offline report. Role expectations
supplied for the strict controlled-resource comparison remain the way to turn a
tentative result into a confirmed one.

## CodeQL (operator-supplied)

CodeQL is not bundled in the image. Its CLI terms allow free use only for
open-source code, academic research and demonstration, require a GitHub
Advanced Security entitlement for other code, and do not allow redistribution,
while this repository publishes images. Registry version 31 therefore adds a
`codeql` source adapter that stays unavailable, with the reason shown in setup
and in the plan, until the operator:

1. downloads a CodeQL bundle for the container's architecture (for example
   `codeql-bundle-linux-arm64.tar.gz` or `codeql-bundle-linux64.tar.gz` from the
   `github/codeql-action` releases) and mounts it, for example at `/opt/codeql`;
2. sets `XALGORIX_CODEQL_PATH=/opt/codeql/codeql`; and
3. sets `XALGORIX_CODEQL_LICENSE_ACCEPTED=1` only if the deployment is entitled
   to analyze the code it will scan.

When available, it is selected automatically for source-code assessments. The
runner detects languages in the prepared checkout (skipping vendored and build
directories) and analyzes, one at a time, those CodeQL extracts without a build:
GitHub Actions workflows, C#, Java, JavaScript/TypeScript, Python and Ruby. The
runtime deliberately has no compilers, so detected C/C++, Go, Kotlin, Swift and
Rust sources are recorded as gaps rather than skipped silently. Each language
runs `database create --build-mode=none` and `database analyze` with the default
code-scanning suite, without downloading query packs; the database (a full copy
of the source) is deleted afterwards and the SARIF is sanitized. Severity follows
each rule's `security-severity` score with GitHub's thresholds, CWE comes from
the rule tags and precision is kept as confidence. A failed language, a spent
time budget (`XALGORIX_CODEQL_TIMEOUT_SECONDS`, default 3600) or a detected
language that needs a build leaves the run partial.

## Out-of-band callback checks (Interactsh)

Ordinary Nuclei jobs keep interactsh disabled (`-ni`) and exclude the `oast`,
`oob` and `interactsh` template tags. Registry version 32 adds an explicitly
consented alternative: setting `oast_callbacks` (the "Allow out-of-band callback
checks" option in setup) plans one extra `nuclei` job with variant
`nuclei-oast` for each target whose ordinary Nuclei job is selected. It runs
only the callback templates; every other excluded tag (rce, dos, intrusive,
brute force, uploads and so on) stays excluded, and it inherits the gateway,
rate, redirect, signed-template and scope rules of Nuclei. Its endpoint coverage
and input manifest are keyed `nuclei-oast` so they never overwrite ordinary
Nuclei coverage. Legacy (non unified-v1) plans warn instead.

Nuclei's default callback servers are ProjectDiscovery's public `oast.*`
services, so payloads naming the target would reach a third party. Xalgorix
never uses them: `XALGORIX_INTERACTSH_SERVER` must be the origin of a
self-hosted `interactsh-server` (for example `https://oast.example.org`), and
public Interactsh hosts are refused. Without a valid server the consented job is
planned as unavailable with the reason. `XALGORIX_INTERACTSH_TOKEN` is the
server's `-token`; it is passed to Nuclei on its command line (like the other
child-process credentials) and redacted from saved output. For internet-facing
targets the server needs a public IP and a domain whose DNS is delegated to it.

Target traffic still passes through the recording gateway. Nuclei polls the
Interactsh server directly, not through the gateway, so that polling is not
recorded as target coverage. A callback is matched only while Nuclei polls (a
20-second cooldown follows the last request); later callbacks, or targets that
cannot reach the server, produce no result, which the run records as a
limitation. Verified with retained Nuclei 3.11.1 and interactsh-server 1.4.1 on
a disposable internal network: the payload reached the local target through the
gateway, the target's callback was matched, the gateway saw only target traffic
and the token did not appear in saved output. Nuclei needs the server as a URL
with a scheme; a bare hostname makes it try HTTPS on port 443 only.

## Detection-only secret, header and exposure checks

Registry version 33 adds four passive detection improvements. None send a
payload, submit a form or change state; each is a read-only GET and
pattern-matching, and no secret value is ever written to the findings artifact.

- **Served-bundle secret scanning (nextjs-assets).** The Next.js asset job
  already downloads every client bundle; it now also scans those bodies (no
  extra request) for curated high-confidence provider credentials (AWS, Google,
  GitHub, GitLab, Slack, Stripe secret/restricted, SendGrid, npm, OpenAI,
  Twilio, Square, FCM, PEM private keys), secret-named `NEXT_PUBLIC_` variables
  misused as the public prefix compiles them into the bundle, and internal or
  non-routable URLs. Publicly safe values (Stripe publishable keys, the Firebase
  web apiKey) are deliberately excluded. Findings name the provider and a safe
  prefix only.
- **`__NEXT_DATA__` config leaks (nextjs-assets).** The serialized page data is
  parsed for secret-named prop keys with real values and for a populated
  `serverRuntimeConfig`/`runtimeConfig` object that reached the client. Evidence
  reports the key path, never the value.
- **Next.js exposed files (exposed-files, catalog v2).** Adds the Next.js env
  family (`.env.development`, `.env.development.local`, `.env.test`) and the
  framework config source (`next.config.js`/`.mjs`/`.ts`). The config classifier
  requires a module export plus a Next.js config-shape marker, so a generic
  served `.js` file is not misreported.
- **Passive security headers (security-headers).** A new web adapter selected
  automatically for URL web/API targets. One GET on the target root, then a
  check for missing/weak HSTS (https only), missing/weak CSP, missing
  clickjacking protection (X-Frame-Options or CSP frame-ancestors), missing
  `X-Content-Type-Options: nosniff`, missing Referrer-Policy, and software
  version banners. Findings map to the existing missing_security_header class so
  ZAP/Nikto results dedupe with them by host. It validates each request through
  the scope guard, so it is gateway-equivalent and carries no direct-egress
  caveat.

# Web application and API scanning workflow

## 1. Purpose and implementation contract

Date: 2026-10-02. Code inspected at HEAD commit `2052bca`.

This document is the implementation plan for the supplied web/API workflow
requirements (reproduced faithfully in section 2). It extends the existing
Xalgorix planner, scanner adapters, attack-surface inventory, authentication,
findings correlation, and reports. It does not introduce a new AI subsystem and
does not expand server, cloud, Kubernetes, code, or monitoring workflows.

### Implementation status

**Not started.** No code in this plan is written yet. Sections 3–7 below describe
the intended work. The requirements in section 2 are the contract; the task
breakdown in section 5 mirrors `scratchpad/webapi/tasks.json`.

Required hierarchy (same house pattern as the capability-planner plan):

```text
Accepted scope and policy establish allowed destinations and exclusions
  -> supplied credentials and OpenAPI inputs establish authenticated/API capabilities
  -> the planner builds dependency-ordered workflow stages with a fingerprint
  -> one shared web/API orchestration path executes the stages
  -> discovery populates an inventory with provenance and eligibility, never new scope
  -> policy-compliant scanners run against eligible, materialized requests only
  -> the findings engine correlates results; coverage and reports stay truthful
```

Build/test rule on macOS: `CGO_ENABLED=0`. Known-environmental test failures
`internal/sandbox` and `internal/resources` are excluded. Pre-existing
uncommitted user runtime work (Dockerfile, `runtime/*`, `tools.md`, docs — see
`scratchpad/webapi/preexisting-dirty.txt`) must be built **on top of**, never
reverted.

## 2. Requirements (the spec)

### 2.1 Summary and boundaries

Build a coordinated web/API assessment workflow using Xalgorix's existing
planner, scanner adapters, attack-surface inventory, authentication, findings
correlation, and reports. The first release covers **one application and its
explicitly approved API origins**. It does not expand server, cloud, Kubernetes,
code, or monitoring workflows.

Decisions:

- REST APIs with OpenAPI 3.0/3.1 or Swagger 2.0 first.
- Existing ZAP and Nuclei adapters plus bounded native API checks; no
  Schemathesis in this release.
- Xalgorix findings and reports first; DefectDojo integration deferred.
- Discovered hosts are candidates, not automatically authorized targets.
- Low-impact testing by default; explicitly approved write operations only in a
  designated test environment.
- Preserve existing UI layouts, palette, assessment modes, and unrelated scanner
  behavior.

### 2.2 Workflow and tool selection

Implement dependency-based stages rather than a shell-command chain. Each stage
has structured inputs, outputs, limits, cancellation, and an explicit completion
or gap reason.

| Stage | Tools | Behavior |
|---|---|---|
| Scope and prerequisites | Native checks | Validate approved origins, path boundaries, exclusions, credentials, scanner availability, and budgets. |
| Optional domain discovery | Subfinder; optional Amass | Gather candidate subdomains using passive discovery. Never expand runnable scope automatically. |
| DNS validation | DNSX | Resolve approved hostnames, retain A/AAAA/CNAME evidence, identify wildcard responses. Skip for IP literals. |
| Reachability and technology | HTTPX | Probe approved origins; collect status, redirects, content type, title, TLS, and technology metadata. |
| Authentication | Existing credential/session adapters | Verify access before authenticated discovery; retain a separate public baseline. |
| Endpoint discovery | Katana | Crawl to depth 5 with structured JS, XHR, and form discovery within approved boundaries. |
| Optional historical discovery | gau; optional waybackurls | Gather archived URL candidates, filter scope, remove sensitive values, and revalidate before dispatch. |
| Inventory | Existing attack-surface engine | Merge crawler, history, manual seeds, and OpenAPI operations with provenance and eligibility reasons. |
| Passive analysis | ZAP passive rules and local response checks | Analyze traffic already collected; distinguish this from active requests. |
| Low-impact template checks | Nuclei | Run a reviewed, pinned template selection against suitable endpoints. |
| TLS assessment | testssl.sh; optional SSLyze | Assess each distinct approved TLS service, preserving hostname/SNI and port identity. |
| DAST | OWASP ZAP | Test policy-approved requests using verified authentication where configured. |
| Targeted validation | Nuclei, Dalfox, native API checks | Run only relevant checks against eligible requests and explicitly supplied API fixtures. |
| Results | Existing correlation and reporting | Preserve observations, correlate findings, update coverage, and generate reports. |

Default choices: subdomain and historical discovery are opt-in (external
services, limited value for private apps). Subfinder is the primary subdomain
adapter, Amass optional enrichment; gau is primary historical, waybackurls an
explicit alternative (not an automatic duplicate run); testssl is the default TLS
adapter, SSLyze optional; Nikto and Wapiti remain through existing optional
controls; SQLMap stays explicit-approval-only and is never automatically
selected. HTTPX already does technology identification, so no extra fingerprinting
tool is needed. Ordinary Nuclei scans send requests and must be labelled active
template checks, not passive scanning.

### 2.3 Execution, scope, authentication, and API behavior

**Scope and safety policy.** Identify allowed destinations by scheme,
hostname/IP, port, and optional application path boundary; a shared hostname or
resolved IP does not merge applications or authorize additional ports. Apply
scope checks to redirects, extracted links, specification servers, generated
scanner requests, and browser requests — not only initial targets. Preserve
existing self-listener protections and explicit local-target permissions; never
silently broaden access to resolve a failed scan. Use exclusions for logout,
deletion, purchases, administrative mutations, and operator-specified routes (GET
is not inherently side-effect-free). Disable templates/rules/adapter modes whose
traffic cannot comply with the policy and record the coverage gap. Disable
brute-force, destructive, arbitrary-code, and external callback/OAST checks by
default. Preserve Gentle defaults: 2 rps, 500 unique endpoints, 30-minute budget,
including discovery, retries, and validation. Coordinate target-contact stages so
scanner-specific rates do not multiply the intended rate; add bounded request
counts, timeouts, retry/backoff, and cancellation. Preserve Thorough as an
explicit choice that must not enable write operations automatically.

**Authentication.** Black Box runs without application credentials; Gray/White
Box may use supported target-bound credentials (White Box does not auto-activate
unrelated code/infra scanners). Support form-login, cookie, header, bearer-token,
and API-key mechanisms. Verify form login with an authenticated success condition
**and** an unauthenticated negative control — a successful response or saved
credential alone is insufficient. Bind credentials to approved destinations;
never forward them to archive providers, discovered sibling hosts, or cross-origin
redirects. Verify authentication before crawling and before authenticated scanner
stages; refresh during long jobs. On session loss, stop dependent authenticated
work and report failed/incomplete coverage — do not silently continue
anonymously. Show `configured`, `verified`, `failed`, and `expired` from actual
execution evidence. Preserve the current standard-engine fallback for
authenticated Katana until the pinned headless implementation passes
credential-propagation tests; show missing browser-executed discovery as a
limitation. Browser SSO/MFA automation remains unsupported; a supplied valid
session may be used if verification succeeds.

**Discovery and inventory.** Retain provenance from every discovery source,
including duplicates. Treat archived URLs as historical candidates, not proof an
endpoint still exists (gau aggregates external archives). Keep unreached,
excluded, stale, static, and unauthorized resources visible with reasons. Reuse
existing canonicalization and stable endpoint identities. Keep executable sample
requests separate from canonical URLs; never send `{value}` placeholders to
scanners or lose parameter values needed for controlled API tests. Keep static
JavaScript as discovery input, not an active scanning target. Preserve method,
parameter location/name, form metadata, authentication context, and API operation
identity.

**API request handling.** Extend the current GET-only OpenAPI adapter rather than
bypassing it: resolve local references, operation parameters, security
requirements, and request-body metadata; continue rejecting remote references;
map specification servers explicitly to approved origins; accept operator-supplied
values for path params, required params, and test bodies (missing inputs become
visible gaps, not guessed requests). Safe default: approved GET/HEAD operations
only, subject to exclusions. Test-environment policy: explicit method-and-path
approval plus supplied fixtures for POST/PUT/PATCH/DELETE; authentication POSTs
are separately permitted as narrowly scoped login operations. Do not auto-retry
write requests; require declared cleanup for resource-creating workflows and
report cleanup failures separately. Do not import an unfiltered spec into ZAP;
feed only approved, materialized operations. Native API checks cover
authentication enforcement, configured authorization expectations, information
disclosure, CORS, content types, and response/schema inconsistency (schema
differences alone are not confirmed vulnerabilities). Object/role-authorization
checks require two supplied test identities, controlled resource fixtures, and
explicit expected access; do not enumerate real customer identifiers or claim
complete business-logic coverage. GraphQL, SOAP, gRPC, WebSocket testing, broad
fuzzing, and inferred business workflows remain documented gaps.

### 2.4 Integration, persistence, and user experience

**Planner and runtime.** Register Amass, DNSX, gau, waybackurls, and SSLyze with
availability, purpose, applicable targets, authentication support, policy
support, and output format. Promote discovery and authentication stages into the
accepted workflow instead of unexplained background activity. Extend plan jobs
with stage and dependency metadata; distinguish prerequisite failure, unavailable
tool, excluded work, empty input, and successful completion. Fingerprint scope,
policy, tool/template versions, input artifacts, and non-secret credential
revision metadata. Discovery may populate approved job inputs but cannot add
destinations or escalate policy; additional scope requires a new preview and
acceptance. Use one shared web/API orchestration path for legacy and typed
assessments; leave non-web execution unchanged.

**APIs and persistence.** Extend existing assessment configuration and APIs
additively with approved origins/exclusions, discovery provider selections, API
operation inputs and write-operation approvals, workflow stage/dependency info and
execution evidence, and operation-level coverage/authentication results. Reuse
existing plan, scan, coverage, attack-surface, output, artifact, and findings
endpoints; preserve old clients and historical scan reads. Persist a versioned
workflow manifest alongside per-scan JSON snapshots (accepted policy, tool
versions, input/output checksums, stage status, timestamps — never credentials).
Resume only completed stages with matching inputs, policy, versions, and valid
artifacts; reverify authentication before resumed authenticated work; never
auto-replay an interrupted write. Redact secrets before storing new artifacts;
preserve stored native artifacts unchanged during parsing, correlation, and
report regeneration.

**UI and reporting.** Keep the four-step flow; expose web/API controls per mode
and target. Review shows tools, dependencies, request policy, expected inputs,
unavailable capabilities, and authentication still awaiting verification. Scan
Detail shows the accepted workflow with live states and direct access to redacted
output and artifacts. Separate discovered, eligible, attempted, completed,
failed, and skipped endpoint/operation counts; where adapters give only
batch-level evidence, say "batch completed" rather than imply every endpoint was
exercised. Preserve the existing findings engine as the single source for unique
findings, statuses, severity totals, and risk. Reports include scope,
authenticated coverage, API operation coverage, excluded work, tool failures, and
evidence limitations. Missing tools, failed login, empty scans, or budget
exhaustion cannot produce an unqualified "clean" result.

### 2.5 Delivery and verification

Five increments: (1) Foundation — scope/policy model, workflow jobs, auth
verification, request-policy enforcement, compatibility tests; (2) Discovery —
new adapters, HTTPX metadata, historical candidates, inventory merging,
deterministic budgets; (3) API testing — OpenAPI materialization, approved
operations, controlled fixtures, ZAP integration, targeted validation; (4)
Visibility — setup controls, live workflow, operation coverage, findings/report
integration, documentation; (5) Release validation — pinned runtime integration,
lab acceptance, regression checks, embedded frontend rebuild.

Add new binaries through the existing runtime lock, provenance manifest, and
smoke tests; pin versions and checksums; disable automatic tool/template updates
during scans; preserve the current uncommitted runtime work. Required test areas,
lab extensions, and verification commands are reproduced in sections 5 and 7.
Release only after scope isolation, credential handling, method restrictions, and
truthful coverage pass; report measured detection results separately —
successful tool execution is not proof of vulnerability coverage.

## 3. Current architecture and gaps

| Requirement area | Current code (file:line) | Integration decision |
|---|---|---|
| Scope/origin/path boundary | Three near-duplicate helpers: `urlWithinApplication` (web/assessment_auth.go:293), `verificationURLWithinTarget` (assessment/validate.go:224), `applicationContextRegex` (scanner/zap.go:71); `inSurfaceHostScope` is hostname-only (scanner/attack_surface.go:190). No origins/exclusions fields. | New leaf `assessment.AppScope` (scope.go) normalizing default ports; add `ApprovedOrigins`/`Exclusions`/`TestEnvironment` to `AssessmentConfig`; make the existing helpers delegate. |
| Self-listener / local-target guard | `scopeguard.IsLocalOrListener` (scopeguard.go:141) used only on submitted targets; preview (`buildAssessmentPlan` scanner_handlers.go:67) never runs it; `internal/scanner` never imports scopeguard. | Run the guard + AppScope on every approved origin at preview; keep IsLocalOrListener unchanged and apply it to discovered destinations. |
| Exclusions | None anywhere (`endpointEligibleForScanner` attack_surface.go:552 is the single gate). | Add exclusions to the dispatch gate; keep excluded endpoints visible with a skip reason. |
| Auth states | `EvidenceState` = declared/available/verified/unavailable (assessment/types.go:151); expiry inferred by substring-matching zap Reason (assessment_coverage.go:99). No negative control (form_auth.go:21, assessment_auth.go:256). | Add `failed`/`expired` states; add `verifyNegativeControl`; record auth status structurally. |
| Credential revision | `credentials.Record`/`Metadata` have no revision; `Replace` keeps ID/CreatedAt (vault.go:152). | Add `Revision`/`UpdatedAt`; feed into the plan fingerprint. |
| Planner stages/deps | `PlanJob.Dependencies` exists but is never populated; no `Stage`; jobs sorted alphabetically (planner.go:241); httpx/katana skipped (planner.go:142). | Add `Stage`, populate `Dependencies`, stage-topological sort, promote discovery/auth stages, bump RegistryVersion "3"->"4". |
| Fingerprint inputs | `planFingerprint` (planner.go:373) hashes config/caps/decisions/jobs/registry only; no tool versions, credential revision, or materialized API ops (appended after fingerprint, scanner_handlers.go:103). | Extend `PlanInput` + `planFingerprint` with tool versions, credential revisions, policy, and materialized operations. |
| Gap kinds | Only free-text `Run.Reason`; no machine-readable kind (assessment_jobs.go). | Add `Run.GapKind` + `Run.Stage` constants. |
| Rate budget | Each builder gets full `RateRPS` independently (nuclei/katana/dalfox); ZAP has none; dalfox multiplies per worker; discovery runs outside `WebBudget` (assessment_jobs.go:298). | Add `Config.AssessmentRPS` shared budget; apply per builder; start `webDeadlines` before discovery. |
| Two web paths | Legacy `Pipeline.Run` (pipeline.go:214, runRecon auto-promotes subfinder hosts) vs typed `RunAssessmentJobs` (assessment_jobs.go:40, katana-only). | Synthesize a compatibility plan for legacy web requests and route through the shared path; keep `pipeline.Run` for non-web. |
| Auth-failure visibility | Discovery auth failure does a bare `continue` (assessment_jobs.go:119): no run, no gap. | Record a failed discovery Run with GapKind and skip dependents. |
| New discovery tools | None of dnsx/gau/waybackurls/amass/sslyze exist in Go; httpx captures no metadata (recon.go:100); typed subfinder never runs (HasAssessmentRunner excludes it). | Add adapters + config/registry/availability plumbing; extend httpx metadata; promote discovery stages. |
| Inventory provenance | `Sources` mixes tool names and referrer URLs; duplicates collapsed; first URL sample kept (attack_surface.go:341). | Add `Provenance[]`, `State`, `SampleRequests[]`; new merge functions. |
| OpenAPI | `ParseOpenAPI` (openapi.go:84) validates but never dereferences refs; ignores servers/security/params/body; GET-only; `MergeOpenAPIEndpoints` leaks `{id}` placeholders and loses subpath. | Deref local refs, resolve params/security/body/servers, GET/HEAD, materialize with operator inputs, one materializer for inventory + ZAP. |
| Write operations | `AllowStateChanging` unused (profile.go); no write-approval model. | Add `WriteApprovals` gated on TestEnvironment; no auto-retry; declared cleanup. |
| Workflow manifest | None; `scan.json`/queue written non-atomically (server.go:2603). | New `WorkflowManifest` at `<scanDir>/workflow/workflow-v1.json` via `storage.WriteAtomic`; resume validation. |
| Coverage/report truthfulness | Coverage lacks stages/auth-states/counts (assessment_coverage.go:46); report prints strong-posture narrative for zero findings even when tools failed (report.go:810). | Extend coverage additively; add a coverage qualifier; label nuclei active template checks. |
| UI | Four-step flow with hardcoded prep list and "HTTP reachability"/"Katana crawl" placeholders (new-scan.tsx, scan-detail.tsx); auth mapping collapses to configured/failed. | Add origins/exclusions/discovery/API-input controls; real stage rows; configured/verified/failed/expired mapping. |
| Runtime | User's uncommitted Debian-slim Dockerfile + `runtime/content-lock.json` + smoke test; no per-binary checksums; PD tools lack `-duc`. | Additive pins/lock entries/smoke probes for the 5 new tools; per-binary sha256; never revert user work. |
| Lab | Single user, no roles/expiry/excluded routes/API CRUD/request log (test/lab/app/main.go). | Extend app + manifest v2 + scorecard gates; request-log proof. |

## 4. Data model changes

All additions are **additive with `omitempty`** so previously saved
plans/schedules fingerprint identically when the fields are unused, and historical
scan reads keep working. `AssessmentConfig` is persisted in four places and
returned by `GET /api/scans/{id}`, so no secret ever goes into it — fixtures and
bodies are referenced by opaque IDs.

### Go types (`internal/assessment/types.go`)

- `AssessmentConfig`: `ApprovedOrigins []ApprovedOrigin` (`approved_origins`),
  `Exclusions []Exclusion` (`exclusions`), `TestEnvironment bool`
  (`test_environment`), `APIOperationInputs []APIOperationInput`
  (`api_operation_inputs`), `WriteApprovals []WriteApproval` (`write_approvals`).
- `ApprovedOrigin{Scheme, Host, Port, PathPrefix}`;
  `Exclusion{Method, PathPattern, Reason}`.
- `APIOperationInput{DefinitionID, OperationID, PathParams map[string]string, Query map[string]string, RequestBodyRef string}`.
- `WriteApproval{Method, Path, FixtureRef, CleanupRef}` (refs are opaque).
- `AccessBinding`: add `NegativeMarker string` (`negative_marker`).
- `EvidenceState`: add `StateFailed = "failed"`, `StateExpired = "expired"`.
- New `AppScope` type + `Allows`/`Excluded` in `internal/assessment/scope.go`.

### Go types (`internal/scanner`)

- `PlanJob`: add `Stage string` (`stage`); populate existing `Dependencies`.
- `ScannerDefinition`: add `Stage string`.
- `PlanInput`: add `ToolVersions map[string]string`,
  `CredentialRevisions map[string]string` (both `json:"-"`).
- `APIEndpoint`: add `OperationID`, `Parameters []{Name,In,Required}`, `Security`,
  `RequestBody{Required,ContentTypes}`, `Servers`, `MissingInputs`.
- `AttackSurfaceEndpoint`: add `State`, `StateReason`,
  `Provenance []EndpointProvenance{Tool,Source,Artifact,ObservedAt,Authenticated}`,
  `SampleRequests []{URL,Method,Body,ContentType}`. **Do not** bump
  `AttackSurfaceSchemaVersion` (keep loading historical snapshots).
- `Run`: add `GapKind string`, `Stage string`.
- `Config`: add `AssessmentRPS int`, `DnsxPath`/`GauPath`/`WaybackurlsPath`/
  `AmassPath`/`SslyzePath` + `*Timeout`.
- New `WorkflowManifest` type (schema_version 1) + `Save/LoadWorkflowManifest`.

### Credentials (`internal/credentials/vault.go`)

- `Record`/`Metadata`: add `Revision int`, `UpdatedAt time.Time`.

### Config / web / TS

- `internal/config/config.go`: new `*Path`/`*TimeoutSec` fields + env loader.
- `WSEvent` (web/server.go): add `job_id`, `stage`, `variant`, `scope`, `status`.
- `webui/src/types/api.ts`: mirror every new field as optional.

### Versioning and compatibility

- Plan `RegistryVersion` "3" -> "4" (forces a fresh preview for stored plans).
- Workflow manifest is new, read strictly (`schema_version` mismatch = "no
  manifest", treated as legacy). `scan.json` gains only optional pointer fields.
- Legacy v1/v2 record fixtures (`internal/web/testdata/legacy/`) keep passing;
  add a workflow-manifest fixture. `GET /coverage` keeps returning the legacy
  state for records without a plan.

## 5. Task breakdown per increment

Each task is sized for one implementer (~150–700 lines incl. tests), is TDD-able,
and leaves the tree compiling with tests green. Within an increment, tasks sharing
a `parallel_group` touch strictly disjoint files and can run concurrently; others
are ordered by `depends_on`. Full machine-readable detail (files, tests,
spec refs) is in `scratchpad/webapi/tasks.json`.

### I1 — Foundation (10 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I1.T1 | A | — | Scope/policy + auth-state model: `ApprovedOrigins`/`Exclusions`/`TestEnvironment`/`NegativeMarker`, `AppScope` matcher, `StateFailed`/`StateExpired`, normalize/validate | assessment/types.go, validate.go, scope.go |
| I1.T2 | A | — | Vault credential revision (`Revision`/`UpdatedAt`, bump in `Replace`) | credentials/vault.go |
| I1.T3 | B | T1 | Unauthenticated negative control for form + header verification | web/auth_negative_control.go, form_auth.go, assessment_auth.go |
| I1.T4 | B | T1 | Planner stage/dependency model, promote discovery/auth stages, stage-topological sort, fingerprint tool versions/credential revisions/policy, RegistryVersion->"4" | scanner/planner.go, descriptor.go |
| I1.T5 | B | T1 | `Run.GapKind`/`Stage`, `Config.AssessmentRPS`, Thorough write-guard | scanner/types.go, profile.go |
| I1.T6 | C | T4,T5 | Request-policy + boundary + exclusion + placeholder refusal at `endpointEligibleForScanner`; keep out-of-scope rows visible | scanner/attack_surface.go |
| I1.T7 | C | T1,T4 | Preview scope guard (IsLocalOrListener+AppScope), fingerprint inputs wiring, flat-field detection keys | web/scanner_handlers.go, server.go |
| I1.T8 | C | T4,T5 | Versioned workflow manifest type + atomic save/load + resume validation | scanner/workflow_manifest.go |
| I1.T9 | D | T7 | One shared web/API orchestration path (legacy web -> compatibility plan); discovered hosts are candidates; no sibling credential forwarding | web/deterministic_scan.go, orchestrator.go |
| I1.T10 | E | T4,T5,T6,T8 | Stage-driven executor: discovery in budget, visible auth-failure gap, dependency gating, shared rate, katana scope regex + `-duc`, manifest-gated resume | scanner/assessment_jobs.go, katana.go |

### I2 — Discovery (7 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I2.T1 | A | — | Config/registry/availability plumbing for dnsx/gau/waybackurls/amass/sslyze | config/config.go, scanner/types.go, pipeline.go, registry.go, web/deterministic_scan.go, scanner_handlers.go |
| I2.T2 | B | T1 | DNSX adapter (A/AAAA/CNAME, wildcard, skip IP literals) | scanner/dnsx.go |
| I2.T3 | B | T1 | gau + waybackurls historical adapters + revalidation | scanner/historical.go |
| I2.T4 | B | T1 | Amass passive subdomain adapter (candidates only) | scanner/amass.go |
| I2.T5 | B | T1 | SSLyze optional TLS adapter (SNI/port identity) | scanner/sslyze.go |
| I2.T6 | C | T1 | HTTPX metadata (status/title/tech/TLS/redirect) + typed-path promotion, no false-live fallback | scanner/recon.go, scope.go |
| I2.T7 | D | T2,T3,T4,T5,T6 | Inventory merge with provenance/state/sample-requests; discovery stages wired into executor; separate public baseline | scanner/attack_surface.go, assessment_jobs.go |

### I3 — API testing (6 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I3.T1 | A | — | API operation inputs + write approvals + fixture references in config/validation | assessment/types.go, validate.go |
| I3.T2 | B | T1 | OpenAPI deref/params/security/servers/Swagger2, HEAD eligible, generalize `apiEndpointURL` | scanner/openapi.go |
| I3.T3 | C | T2 | Materialize operations with operator inputs; one materializer; no placeholders; preserve subpath | scanner/attack_surface.go, api_materialize.go |
| I3.T4 | C | T2 | ZAP approved materialized operations + named scan policy (disable brute-force/OAST/destructive) + exclusions + rate delay | scanner/zap.go |
| I3.T5 | D | T3 | Native API checks (authn/authz-two-identities/info-disclosure/CORS/content-type/schema) + targeted validation; no write auto-retry | scanner/apichecks.go, registry.go, assessment_jobs.go |
| I3.T6 | D | T3 | Web plan materializes operations into fingerprinted inputs | web/scanner_handlers.go |

### I4 — Visibility (7 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I4.T1 | A | — | Coverage API: stages, auth states, endpoint counts, evidence level | web/assessment_coverage.go |
| I4.T2 | A | — | Report coverage qualifier (no unqualified clean), active-template labels, limitations | web/report.go, report_coverage.go |
| I4.T3 | A | — | WSEvent stage/job fields + emit; attack-surface API provenance/state; `?variant=` output selector | web/server.go, deterministic_scan.go, attack_surface.go |
| I4.T4 | B | T1,T3 | TypeScript type mirror for all new fields | webui/src/types/api.ts |
| I4.T5 | C | T4 | New-scan setup controls: origins/exclusions, discovery providers, negative control, API inputs/write approvals (test-env), richer Review | webui/src/pages/new-scan.tsx, api/client.ts |
| I4.T6 | C | T4 | Scan-detail real stage rows, auth states, operation counts, surface provenance/state | webui/src/pages/scan-detail.tsx |
| I4.T7 | D | T5,T6 | User-facing workflow documentation | docs/web-api-workflow.md |

### I5 — Release validation (6 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I5.T1 | A | — | Runtime lock + Dockerfile pins + per-binary checksums (additive on user tree) | Dockerfile, runtime/content-lock.json, write-content-manifest.py, test_content_manifest.py |
| I5.T2 | A | — | Smoke-test coverage for new tools (offline) | runtime/smoke-test.py |
| I5.T3 | B | — | Lab fixtures: authenticated REST API, roles, origins, expiry, exclusions, history, manifest v2 | test/lab/app/main.go, manifest.v2.json, compose.yaml |
| I5.T4 | C | T3 | Scorecard safety gates + baseline runner | test/lab/scorecard/main.go, run_baseline.py |
| I5.T5 | D | I4.T5,I4.T6 | Embedded frontend asset refresh (deliberate; scratch build + copy) | internal/web/static/{app.js,style.css,index.html} |
| I5.T6 | E | all | Full regression, plan status flip, validation.md record | docs plan, runtime/validation.md |

## 6. Explicit deferrals / documented gaps

- Schemathesis API fuzzing (section 2.1) — ZAP + Nuclei + native checks cover
  the first release.
- DefectDojo integration (2.1) — Xalgorix findings/reports first.
- Browser SSO/MFA automation (2.3) — unsupported; a supplied valid session may be
  used when verification succeeds.
- Pinned headless authenticated Katana (2.3) — standard-engine fallback preserved;
  missing browser-executed discovery surfaced as a coverage limitation.
- GraphQL, SOAP, gRPC, WebSocket, broad fuzzing, inferred business workflows
  (2.3) — documented gaps.
- SQLMap automatic selection (2.2) — explicit-approval-only; no auto path added.
- Live EPSS/KEV risk feeds and auto-`VERIFIED` finding status — out of scope; the
  findings engine stays the single source and technology detections stay
  observations.
- Multi-user roles / tamper-proof audit — not in this spec.
- Server/cloud/Kubernetes/code/monitoring workflow expansion (2.1) — first release
  is one application and its approved API origins only.

## 7. Verification commands

Run focused tests per task, then full gates at increment boundaries. On macOS use
`CGO_ENABLED=0` and exclude the environmental `internal/sandbox` and
`internal/resources` failures.

```sh
# Focused (foundation / discovery / API / web)
CGO_ENABLED=0 go test ./internal/assessment/... ./internal/scanner/... ./internal/web/... ./internal/credentials/... ./internal/storage/...

# Full Go gates (exclude environmental macOS failures)
CGO_ENABLED=0 go test $(go list ./... | grep -v '/internal/sandbox' | grep -v '/internal/resources') -timeout 15m
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go vet ./...
gofmt -l internal cmd test

# WebUI (no in-tree build; typecheck + scratch build)
(cd webui && ./node_modules/.bin/tsc -p tsconfig.app.json --noEmit && ./node_modules/.bin/tsc -p tsconfig.node.json --noEmit)
(cd webui && ./node_modules/.bin/vite build --outDir /tmp/xalgorix-static --emptyOutDir)

# Runtime manifest + offline smoke (lock-aware)
python3 runtime/test_content_manifest.py
docker build . -t xalgorix:local
docker run --rm --network none --entrypoint python3 xalgorix:local /usr/local/share/xalgorix/smoke-test.py

# Linux Docker lab acceptance + whitespace
docker compose -f test/lab/compose.yaml build
python3 test/lab/run_baseline.py
git diff --check

# Embedded asset refresh (final, deliberate — I5.T5)
cp /tmp/xalgorix-static/app.js /tmp/xalgorix-static/style.css /tmp/xalgorix-static/index.html internal/web/static/
node --check internal/web/static/app.js
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./internal/web/...
```

Release only after scope isolation, credential handling, method restrictions, and
truthful coverage pass. Report measured detection results separately; successful
tool execution is not proof of vulnerability coverage.

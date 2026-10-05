# Web application and API scanning workflow

## 1. Purpose and implementation contract

Date: 2026-10-02. Code inspected at HEAD commit `2052bca`. Revised after a
coverage, fidelity and sequencing critique; the resolution log is in section 8.

This document is the implementation plan for the supplied web/API workflow
requirements (reproduced faithfully in section 2). It extends the existing
Xalgorix planner, scanner adapters, attack-surface inventory, authentication,
findings correlation, and reports. It does not introduce a new AI subsystem and
does not expand server, cloud, Kubernetes, code, or monitoring workflows.

### Implementation status

**Foundation and discovery in progress.** Scope, authentication checks, shared
budget, journal-gated resume, stage records, Katana, Nuclei, adapter and ZAP
policy are implemented with tests. The typed executor promotes auth, DNSX,
HTTPX, Katana, Subfinder, Amass, and optional archive providers into stage
jobs; it blocks a crawl when its prerequisites fail. Discovery evidence does
not expand accepted origins. OpenAPI GET/HEAD eligibility, local reference
resolution, and scoped inventory visibility are implemented; unresolved
operations remain non-dispatchable. Preview exposes parameter, body, security,
and declared-server requirements. The setup form selects discovery providers,
route exclusions, and API coverage separates native per-operation checks from
ZAP batch-level outcomes. The operator guide documents supported
behavior and current API limitations. TLS adapters and pinned runtime
integration are implemented and smoke-tested. A private, content-addressed API
fixture store and validated API operation-input, write-approval, and
authorization-expectation config models are implemented. POST approvals now
require an explicit, in-scope, non-excluded cleanup request. Supplied path and
query values now materialize safe GET/HEAD operations; API write approvals are
executed once by the native adapter, with journaled intent and explicit
in-scope cleanup. Remaining work includes legacy web routing, API fixture materialization,
two-identity checks, embedded UI refresh, and release validation. Native checks
currently cover declared-auth enforcement, credentialed CORS, and approved
writes. Sections
3–7 remain the intended complete workflow.

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

### Repository premise

- The Debian-slim runtime work (Dockerfile, `runtime/*`, `tools.md`, docs) is
  part of the current main snapshot. This workflow extends that runtime;
  nothing in this plan reverts it.
- `2052bca` also tracks `runtime/__pycache__/write-content-manifest.cpython-314.pyc`
  and `test/lab/__pycache__/run_baseline.cpython-314.pyc`. Every Python command
  in this plan runs with `PYTHONDONTWRITEBYTECODE=1` so these binaries are not
  rewritten. They are flagged to the user, not deleted.
- `.gitignore` ignores `*.json`. New JSON fixtures are generated under
  `t.TempDir()` in Go tests where possible. Any JSON file that must be committed,
  such as `test/lab/manifest.v2.json`, is added with `git add -f`, as
  `test/lab/manifest.v1.json` already is. Lab OpenAPI fixtures use YAML, which
  `ParseOpenAPI` accepts. The existing `internal/web/testdata/legacy/*.json`
  fixtures are present locally but untracked. This is flagged to the user and
  left unchanged.

### Execution rules

- Build/test on macOS with `CGO_ENABLED=0`. `internal/sandbox` and
  `internal/resources` have known environmental failures and are excluded.
- Within an increment, tasks that share a `parallel_group` touch disjoint files,
  checked mechanically when tasks.json is generated. Several of these tasks still
  write into the same Go package (`internal/scanner`, `internal/web`), so each
  parallel task runs in its own git worktree. At every group boundary the
  worktrees are merged and the full package test suite runs before the next
  group starts.
- New test helpers carry a file-specific prefix (for example
  `dnsxTestFakeTool`, `zapPolicyTestServer`) so that parallel test files cannot
  redeclare the same name.
- Existing exported signatures stay as thin wrappers when a task adds a scoped
  variant (`ParseKatanaAttackSurface`, `DispatchTargets`, `apiEndpointURL`). This
  keeps every task compiling without editing files owned by other tasks.
- `RegistryVersion` is bumped in each increment that changes registry or seeding
  semantics: "4" in I1 (stages and fingerprint inputs), "5" in I2 (new tools and
  stages) and "6" in I3 (operation materialization). Each bump invalidates stored
  plans and schedules once, and I1.T10 makes that visible as a needs-review
  state. Any increment can therefore ship on its own.
- No `npm run build` in-tree. The embedded asset refresh is the deliberate task
  I5.T5.

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
| Scope/origin/path boundary | Three near-duplicate helpers compare `u.Host` (port included, so `https://a` and `https://a:443` differ): `urlWithinApplication` (web/assessment_auth.go:293), `verificationURLWithinTarget` (assessment/validate.go:224), `applicationContextRegex` (scanner/zap.go:71, also used by openapi.go:70). `inSurfaceHostScope` checks only the hostname (scanner/attack_surface.go:190). `scanner.Scope` already has `Origin`/`PathPrefix` (scope.go:32). There are no origin or exclusion fields. | Add a leaf `assessment.AppScope`. It cannot live in `scanner`, because `scanner` imports `assessment`. It normalizes default ports and `AppScopeForTarget` gives legacy configs a boundary. `ApprovedOrigin` carries a `TargetID` and `Exclusion` an optional `TargetID`/`Origin`. Each helper is delegated by a named task: validate.go in I1.T1, `urlWithinApplication` in I1.T3, `inSurfaceHostScope` in I1.T6, `applicationContextRegex` in I1.T15. `scanner.Scope.Origin`/`PathPrefix` are filled from AppScope. |
| Self-listener / local-target guard | `s.isBlockedTargetForScan` (codescan.go:11) builds the full scopeguard config and runs only in runMultiScan (orchestrator.go:29). Preview never runs it. `internal/scanner` never imports scopeguard, and `LookupHost` fails open. | Preview reuses `isBlockedTargetForScan` on targets and ApprovedOrigins (I1.T7). An injected `scanner.Config.ScopeGuard` hook, wired in I1.T9, re-checks hosts at execution time: DNSX results (I2.T2, the rebinding/DNS-change case), historical revalidation (I2.T3), API checks (I3.T6) and SPA validation (I1.T16). |
| Exclusions | None anywhere. `endpointEligibleForScanner` (attack_surface.go:552) is the only dispatch gate. Katana GET-crawls every linked route, including `/logout`. | Stamp `State` at parse/merge time so the gate stays pure (I1.T6). Exclusions also go into katana `-cos` (I1.T12), ZAP context/spider/scan exclusions (I1.T15), historical revalidation (I2.T3) and the Wapiti `-x` / Nikto restriction (I1.T14). |
| Auth states | `EvidenceState` = declared/available/verified/unavailable (assessment/types.go:151). Every verification failure is recorded as `StateUnavailable` (assessment_auth.go:86/98), and the skip gates match only unavailable (:313). Expiry is inferred by substring-matching the zap Reason (assessment_coverage.go:99). There is no negative control. The refresher allows one re-login per scan (:168). | Add `failed`/`expired`. I1.T3 sets failed, makes the gates block on failed/expired, runs the negative control once per verification and bounds renewal to a count. `Run.AuthState` (I1.T5) is set by the executor (I1.T17) and the ZAP monitor (I1.T15). Coverage reads it (I4.T1). |
| Credential revision | `credentials.Record`/`Metadata` have no revision. `Replace` keeps ID/CreatedAt (vault.go:152). | Add `Revision`/`UpdatedAt` and feed them into the plan fingerprint. |
| Planner stages/deps | `PlanJob.Dependencies` exists but is never populated. There is no `Stage`. Jobs are sorted alphabetically (planner.go:241). httpx/katana are skipped (planner.go:142). `HasAssessmentRunner` is false for httpx/katana/subfinder, so `assessmentScannerAvailability` (scanner_handlers.go:123) would mark promoted stages unavailable, and the job loop would report "no execution adapter". | I1.T4 adds Stage, Dependencies, the topological sort, PolicySupport and OutputFormat, without new jobs. I1.T18 promotes katana and auth as stage-executor jobs that are routed away from `byName`, use binary-presence availability and are excluded from type completeness. I2.T9 promotes the discovery tools once their executors exist. |
| Fingerprint inputs | `planFingerprint` (planner.go:373) hashes config/caps/decisions/jobs/registry. Policy fields are hashed through cfg. Schedules refuse silently on drift (schedules.go:120, scheduler.go:330). | Add tool versions, read only from the build-time content manifest and never from executing binaries, plus credential revisions. Drift shows as a needs-review state (I1.T10). Materialized API operations need no extra fingerprint input: definition IDs are content hashes, and the operator inputs are part of the config. |
| Gap kinds | Only free-text `Run.Reason`. | `Run.GapKind`, including budget_exhausted, auth_failed, auth_expired, cancelled and interrupted_write, plus `Run.Stage`, `Run.AuthState` and `Run.Limitations`. |
| Rate budget | `Config.RateRPS` is already the single rate source, set from the profile at assessment_jobs.go:59, and jobs run sequentially. The multipliers are intra-tool: katana `-c 10`, nuclei's default concurrency, dalfox `--worker 10`, ZAP with no delay, and typed Thorough without nuclei `-rl` (pipeline.go:1015). Deadlines are per target (assessment_jobs.go:96/285) and the 500 cap is per scanner. Native HTTP clients and `ValidateSPAFallback` (called with `context.Background()` from findings_correlation.go:72) sit outside any budget. | No new `AssessmentRPS` is added. `AssessmentBudget` (I1.T5) holds one shared limiter, one deadline and one unique-endpoint cap per assessment, and the executor (I1.T11) creates it. Per-tool concurrency, retry and timeout bounds come from katana (I1.T12), nuclei (I1.T13), dalfox (I1.T14) and ZAP (I1.T15). Findings rebuilds make no network requests (I1.T16). |
| Tool policy | `buildNuclei` (pipeline.go:984) runs the whole template dir with `-pt http,headless` and no tag exclusions, and legacy nuclei lacks `-ni -dr`. Wapiti submits forms and has no module allowlist. Dalfox mines parameters, uses 10 workers and receives no auth headers despite `SupportsAuthentication`. Nikto ignores exclusions. | Nuclei gets a reviewed policy: `-pt http`, `-etags` and always `-ni -dr`, with excluded categories recorded as a limitation (I1.T13). Wapiti and Nikto are restricted with a visible gap whenever the policy cannot be honoured. Dalfox is constrained (I1.T14). The planner shows restrictions at preview (I1.T18). |
| Two web paths | Legacy `Pipeline.Run` (pipeline.go:214) vs typed `RunAssessmentJobs` (assessment_jobs.go:40). Typed ZAP requires `ZAPDedicated` (zap.go:115). Legacy wildcard fan-out is in deterministic_scan.go:217; it calls `exec.LookPath("subfinder")` and forwards TargetAuth to siblings (:257). | I1.T9 makes wildcard candidates credential-free and runs the configured subfinder with `-duc`. I1.T19 adds the compatibility plan: an explicit ZAP/spider/rate mapping, scopes split by kind, legacy TargetAuth skipped as unverifiable, and in-flight legacy records finishing on the legacy path. |
| Auth-failure visibility | Discovery auth failure does a bare `continue` (assessment_jobs.go:119). Expiry during nuclei/katana is never detected. | I1.T11 records a failed auth Run and skips dependents. I1.T17 adds a per-target expired state, post-run re-verification and downgrade. |
| Resume | Completed-run reuse is keyed by scope/scanner/variant/fingerprint plus `VerifyChecksum` (assessment_jobs.go:91/208). Failed or cancelled runs re-execute, which would replay writes. `scan.json`/queue writes are not atomic (server.go:2619, queue_state.go). | The manifest is a derived record (I1.T8). The reuse key gains stage input checksums that include upstream outputs (I1.T17). A write-intent journal blocks replay (I1.T8/I1.T17). Writes go through `storage.WriteAtomic` (I1.T7). `AttackSurfaceClassifierVersion` is bumped (I1.T6). |
| New discovery tools | None of dnsx/gau/waybackurls/amass/sslyze exist in Go. httpx captures no metadata (recon.go:100). Typed subfinder never runs. `ParseRun` (parse.go:167) errors on unknown scanners. Legacy `NewPipeline.Runners` runs every registered runner. | Register the new tools in registry.go with `Available:false` (Catalog unchanged), never in `NewPipeline.Runners` or `OrderedNames`. Evidence-only tools return `nil,nil` from ParseRun (I2.T1). Add a typed subfinder adapter (I2.T4), a parser and findingRules for sslyze (I2.T5), and per-service testssl/sslyze runs (I2.T7). Runtime pins for these tools land in I2.T10. |
| Inventory provenance | `Sources` mixes tool names and referrer URLs. Duplicates are collapsed and the first URL sample is kept (attack_surface.go:341). URLs carrying tokens are stored verbatim. | Add `Provenance[]`, `State` and `SampleRequests[]` (bodies stored by reference). Add merge functions, including manual seeds. Redact sensitive query values before storage (I2.T8). |
| OpenAPI | `ParseOpenAPI` (openapi.go:84) already accepts OpenAPI 3.0/3.1 and Swagger 2.0, and definition IDs are sha256 content hashes. It never dereferences refs and ignores servers, host/basePath, security, params and bodies. It is GET-only. `MergeOpenAPIEndpoints` leaks `{id}` placeholders and loses the subpath. | Dereference local refs. Resolve params, security, bodies, OpenAPI 3 servers and Swagger 2.0 host/basePath/schemes. Allow GET/HEAD. Extend the dispatch contract with `DispatchRequest` (I3.T2). One materializer feeds both the inventory and ZAP (I3.T4). |
| Write operations | `AllowStateChanging` is false for both profiles but never read. There is no write-approval model, fixture store, executor or cleanup. | `WriteApprovals`, `AuthorizationExpectations` and identities (I3.T1). A content-addressed fixture store (I3.T3). The native write executor is the only component that sends writes: exactly once, journaled, with declared cleanup (I3.T7). Per-identity sessions (I3.T9). |
| Passive analysis | No passive-only stage. | A ZAP passive variant (I3.T5) and local response checks over collected metadata (I3.T10), labelled passive. |
| Coverage/report truthfulness | Coverage lacks stages, auth states and counts (assessment_coverage.go:46). `CompleteEndpointCoverage` marks every dispatched endpoint completed. The report prints a strong-posture narrative for zero findings even when tools failed (report.go:810). | `batch_completed` (I1.T6). Coverage state derived from structured gap kinds and auth states (I4.T1). A report qualifier (I4.T2). |
| UI | Four-step flow with a hardcoded prep list and "HTTP reachability"/"Katana crawl" placeholders (new-scan.tsx, scan-detail.tsx). The auth mapping collapses to configured/failed. | Types and client in I4.T4. Controls in I4.T5. Workflow, auth, counts and schedule review state in I4.T6. |
| Runtime | Committed at `2052bca`: Debian-slim Dockerfile, `runtime/content-lock.json` (with `version_commands`) and the smoke test. No per-binary checksums. README policy: bundled tools are required (fail closed). | Pins, required lock entries and smoke probes for the five new tools ship with I2 (I2.T10). Checksums and consistency hardening come in I5.T1. `-duc` is set in the Go builders. |
| Lab | Single user, no roles/expiry/excluded routes/API CRUD/request log (test/lab/app/main.go). gau/waybackurls have hardcoded archive endpoints. | Two lab tasks (I5.T2/T3). The history stub works through fake binaries configured via `XALGORIX_GAU_PATH`/`XALGORIX_WAYBACKURLS_PATH`. Scorecard gates are backed by request logs (I5.T4). |

## 4. Data model changes

All additions are **additive with `omitempty`**, and historical scan reads keep
working. `AssessmentConfig` is persisted in four places and returned by
`GET /api/scans/{id}`, so no secret ever goes into it. Fixtures and bodies are
referenced by content-hash IDs.

### Go types (`internal/assessment`)

- `AssessmentConfig`: `ApprovedOrigins []ApprovedOrigin`, `Exclusions []Exclusion`,
  `TestEnvironment bool`, `DiscoveryProviders *DiscoveryProviders`,
  `ManualSeeds []string` (I1.T1); `APIOperationInputs`, `WriteApprovals`,
  `AuthorizationExpectations` (I3.T1).
- `ApprovedOrigin{TargetID, Scheme, Host, Port, PathPrefix}`;
  `Exclusion{TargetID, Origin, Method, PathPattern, Reason}`.
- `DiscoveryProviders{Subdomain []string (subfinder|amass), Historical string (gau|waybackurls|none), TLS string (testssl|sslyze)}`.
- `APIOperationInput{DefinitionID, OperationID, PathParams, Query map[string]string, RequestBodyRef}`.
- `WriteApproval{TargetID, Method, Path, OperationID, FixtureRef, CleanupRef}`;
  `AuthorizationExpectation{OperationID, Identity, Expect, ResourceFixtureRef}`.
- `AccessBinding`: add `NegativeMarker`, `Identity`, `Role`.
- `EvidenceState`: add `StateFailed`, `StateExpired`.
- `AppScope` (scope.go) with `Allows`/`Excluded`/`Origins` and
  `AppScopeForTarget`; `WritesPermitted(cfg)`.

### Go types (`internal/scanner`)

- `PlanJob`: add `Stage`; populate `Dependencies`.
- `ScannerDefinition`: add `Stage`, `PolicySupport []string`, `OutputFormat`.
- `PlanInput`: add `ToolVersions`, `CredentialRevisions` (both `json:"-"`).
- `Run`: add `GapKind`, `Stage`, `AuthState`, `AuthCheckedAt`,
  `Limitations []RunLimitation{Kind, Reason}`.
- `Request`: add `AppScope *assessment.AppScope`, `TestEnvironment`,
  `DispatchRequests []DispatchRequest{Method, URL, BodyRef, ContentType, OperationID}`.
- `Config`: add `ScopeGuard` hook and `Budget *AssessmentBudget` (both
  `json:"-"`); new tool `*Path`/`*Timeout` (I2.T1);
  `AssessmentIdentityHeaders` (I3.T7). There is **no** `AssessmentRPS`:
  `RateRPS` stays the single rate source.
- `APIEndpoint`: add `OperationID`, `Parameters`, `Security`, `RequestBody`,
  `Servers`, `MissingInputs`, `Approved`, `MaterializedURL`, `BodyRef`, `State`.
- `AttackSurfaceEndpoint`: add `State`, `StateReason`, `Provenance[]` and
  `SampleRequests[]` (`BodyRef`, not inline bodies). `AttackSurfaceSchemaVersion`
  is unchanged. `AttackSurfaceClassifierVersion` goes 1 -> 2, which re-parses
  cached snapshots from raw JSONL without contacting the target.
  `CompleteEndpointCoverage` adds a `batch_completed` status.
- `HostEvidence`: add `DNS []DNSRecord`, `HTTP []HTTPObservation`.
- New `AssessmentBudget`, `WorkflowManifest` (schema 1, derived record) and
  `WriteJournal` (schema 1, a gate for writes).

### Credentials, config, web, TS

- `credentials.Record`/`Metadata`: `Revision int`, `UpdatedAt time.Time`.
- `internal/config/config.go`: new `*Path`/`*TimeoutSec` fields and env loader.
- `WSEvent`: `job_id`, `stage`, `variant`, `scope`, `status`. Schedule records:
  `review_state`, `review_reason`. New `/api/api-fixtures` store.
- `webui/src/types/api.ts`: every new field mirrored as optional.

### Versioning and compatibility

- `RegistryVersion` goes "3" -> "4" (I1), "5" (I2), "6" (I3 native checks),
  and "7" when API operation materialization is enabled. Each bump
  invalidates stored plans and schedules **once**. Schedules show `needs_review`
  and are not silently skipped, and paused instances return 409 with a
  re-preview hint. Within a registry version, a config that leaves the new fields
  empty serialises and fingerprints exactly as before. Saved plans therefore do
  **not** fingerprint identically across the bump, which corrects the claim in
  the previous revision.
- Tool and template versions come only from the build-time content manifest, so
  the fingerprint changes on an image upgrade but never between preview and
  start. The workflow manifest records versions per stage, so resume invalidates
  only the stages whose tool changed.
- The workflow manifest and write journal are read strictly: a `schema_version`
  mismatch means "no manifest" (legacy). A corrupt journal is treated as
  unresolved, never as empty. `scan.json` gains only optional fields and is
  written atomically.
- The legacy v1/v2 record fixtures (`internal/web/testdata/legacy/`) keep
  passing. `GET /coverage` keeps returning the legacy state for records without a
  plan. Legacy records started before the upgrade finish on the legacy path.

## 5. Task breakdown per increment

Each task is sized for one implementer (~150–700 lines including tests), is
TDD-able, and leaves the tree compiling with tests green. Within an increment,
tasks that share a `parallel_group` touch strictly disjoint files (checked when
tasks.json is generated) and run concurrently in separate worktrees. Groups run
in letter order, and `depends_on` may also point at earlier increments. The
files, tests and spec references for every task are in
`scratchpad/webapi/tasks.json`. Task counts: I1 19, I2 10, I3 11, I4 7, I5 6 (53 total).

### I1 — Foundation (19 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I1.T1 | A | — | Scope/policy, discovery-provider and auth-state model | assessment/types.go, assessment/validate.go, assessment/scope.go |
| I1.T2 | A | — | Credential revision metadata in the vault | credentials/vault.go |
| I1.T3 | B | T1 | Authentication verification truth: negative control, failed state, bounded renewal | web/auth_negative_control.go, web/assessment_auth.go |
| I1.T4 | B | T1 | Planner stage/dependency model, registry metadata, provider selection, fingerprint inputs (no new jobs) | scanner/planner.go, scanner/descriptor.go, scanner/registry.go |
| I1.T5 | B | T1 | Run gap kinds/auth state/limitations, request scope fields, assessment-wide budget | scanner/types.go, scanner/budget.go, ratelimit/ratelimit.go |
| I1.T6 | C | T4, T5 | Request-policy, boundary and exclusion checks at the single dispatch gate | scanner/attack_surface.go |
| I1.T7 | C | T1, T2, T4 | Preview scope guard, tool-version source, flat keys, atomic scan/queue writes | web/scanner_handlers.go, web/server.go, web/queue_state.go, web/orchestrator.go, web/tool_versions.go |
| I1.T8 | C | T4, T5 | Workflow manifest (derived record) and write-intent journal | scanner/workflow_manifest.go, scanner/write_journal.go |
| I1.T9 | D | T5, T7 | Legacy wildcard: credential-free candidates, configured subfinder, scope-guard wiring | web/deterministic_scan.go |
| I1.T10 | D | T4, T7 | Schedule fingerprint drift becomes a visible needs-review state | web/schedules.go, web/scheduler.go |
| I1.T11 | E | T4, T5, T6, T8 | Stage-driven executor: assessment-wide budget, stage gating, discovery stamping | scanner/assessment_jobs.go |
| I1.T12 | E | T1, T5 | Katana crawl policy: scope regex, exclusions, redirects, concurrency, -duc | scanner/katana.go |
| I1.T13 | E | T5 | Nuclei reviewed template policy, rate and retries | scanner/pipeline.go |
| I1.T14 | E | T1, T5 | Optional adapter policy: Dalfox, Wapiti, Nikto | scanner/adapter_policy.go, scanner/dalfox.go, scanner/wapiti.go, scanner/nikto.go |
| I1.T15 | E | T1, T5 | ZAP scope, exclusions, rate delay and structured session expiry | scanner/zap.go |
| I1.T16 | E | T5 | Findings rebuild never contacts targets outside a scan | scanner/fallback.go, web/findings_correlation.go |
| I1.T17 | F | T11, T3 | Executor auth outcomes and journal-gated resume | scanner/assessment_jobs.go |
| I1.T18 | G | T4, T17, T14 | Promote crawl and auth stages to plan jobs with executors and policy restrictions | scanner/planner.go, scanner/registry.go, scanner/assessment_jobs.go, web/scanner_handlers.go, web/assessment_coverage.go |
| I1.T19 | H | T6, T9, T17, T18 | Legacy WEB/URL/DOMAIN requests through the shared path (compatibility plan) | web/legacy_compat.go, web/deterministic_scan.go |

### I2 — Discovery (10 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I2.T1 | A | — | Config/registry/availability plumbing and HostEvidence fields for new tools | config/config.go, scanner/types.go, scanner/pipeline.go, scanner/registry.go, scanner/scope.go, … |
| I2.T2 | B | T1 | DNSX resolution-validation adapter with wildcard and rebinding detection | scanner/dnsx.go |
| I2.T3 | B | T1 | gau / waybackurls historical candidates with scoped revalidation | scanner/historical.go |
| I2.T4 | B | T1 | Typed Subfinder (primary) and Amass (optional) subdomain adapters | scanner/subdomain.go, scanner/amass.go |
| I2.T5 | B | T1 | SSLyze adapter, parser and findings correlation with testssl | scanner/sslyze.go, scanner/parse.go, scanner/findings.go |
| I2.T6 | B | T1 | HTTPX reachability/technology metadata (typed and legacy) | scanner/recon.go |
| I2.T7 | C | T5, T6 | Per-service TLS enumeration for testssl and SSLyze execution | scanner/tls_services.go, scanner/testssl.go, scanner/assessment_jobs.go |
| I2.T8 | D | T2, T3, T4, T6 | Inventory merge with provenance, manual seeds, sample requests and redaction | scanner/attack_surface.go, scanner/surface_redact.go, scanner/parse.go |
| I2.T9 | E | T7, T8, I1.T18 | Discovery stages wired into the executor and plan | scanner/assessment_jobs.go, scanner/planner.go, web/scanner_handlers.go |
| I2.T10 | D | T1 | Runtime pins, lock entries and smoke probes for the five new tools | Dockerfile, runtime/content-lock.json, runtime/smoke-test.py, runtime/README.md |

### I3 — API testing (11 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I3.T1 | A | — | API inputs, write approvals, identities and authorization expectations in the config | assessment/types.go, assessment/validate.go |
| I3.T2 | A | I1.T1 | OpenAPI adapter: deref, parameters, security, servers (OpenAPI 3 + Swagger 2.0), HEAD, dispatch contract | scanner/openapi.go, scanner/types.go |
| I3.T3 | B | T1 | Content-addressed API fixture store and flat request keys | web/api_fixture_handlers.go, web/server.go |
| I3.T4 | B | T1, T2 | Operation materialization into the inventory (no placeholders, subpath preserved) | scanner/api_materialize.go, scanner/attack_surface.go, scanner/assessment_jobs.go |
| I3.T5 | C | T2, T4 | ZAP scan policy, approved safe operations only, passive-only mode | scanner/zap.go |
| I3.T6 | C | T4 | Native API checks runner (read-only checks) | scanner/apichecks.go, scanner/registry.go, scanner/assessment_jobs.go, scanner/parse.go, scanner/findings.go |
| I3.T7 | D | T6, T3, I1.T8 | Approved-write executor and two-identity authorization checks | scanner/apichecks_writes.go, scanner/apichecks_authz.go, scanner/types.go |
| I3.T8 | D | T4, T3 | Web plan materializes operations at preview (registry v6) | web/scanner_handlers.go, scanner/planner.go |
| I3.T9 | D | T1, I1.T3 | Per-identity authentication sessions | web/assessment_auth.go, web/deterministic_scan.go |
| I3.T10 | E | T5, T8, I2.T6 | Passive analysis stage: ZAP passive job and local response checks | scanner/passive_checks.go, scanner/planner.go, scanner/assessment_jobs.go |
| I3.T11 | E | T4, I1.T13, I1.T14 | Targeted validation routing for Nuclei and Dalfox | scanner/pipeline.go, scanner/dalfox.go |

### I4 — Visibility (7 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I4.T1 | A | I1.T3, I1.T5, I1.T17, I1.T15 | Coverage API from structured evidence: stages, auth states, operation counts | web/assessment_coverage.go |
| I4.T2 | B | T1 | Report truthfulness: coverage qualifier, active-template labels, limitations | web/report.go, web/report_coverage.go, web/report_ai.go |
| I4.T3 | A | — | WSEvent stage/job fields, output variant selector, state-aware attack-surface API | web/server.go, web/deterministic_scan.go, web/attack_surface.go, web/scanner_handlers.go |
| I4.T4 | B | T1, T3 | TypeScript types, API client and queries for all new fields | types/api.ts, api/client.ts, api/queries.ts |
| I4.T5 | C | T4 | New-assessment setup controls | pages/new-scan.tsx |
| I4.T6 | C | T4 | Scan-detail live workflow, auth states, operation coverage, schedule review state | pages/scan-detail.tsx, components/scanner-terminal.tsx, pages/schedules.tsx |
| I4.T7 | C | T4 | User-facing workflow documentation including legacy deltas | docs/web-api-workflow.md |

### I5 — Release validation (6 tasks)

| Task | Group | Depends | Summary | Key files |
|---|---|---|---|---|
| I5.T1 | A | — | Runtime checksum hardening, lock consistency and smoke assertions | runtime/content-lock.json, runtime/write-content-manifest.py, runtime/smoke-test.py |
| I5.T2 | A | — | Lab part 1: request log, roles, REST CRUD, second origin | test/lab/app/main.go, test/lab/compose.yaml |
| I5.T3 | B | T2 | Lab part 2: CSRF/expiry, excluded routes, history stub, vulnerable fixtures, manifest v2, OpenAPI fixtures | test/lab/app/main.go, test/lab/manifest.v2.json, test/lab/openapi/lab-api.v3.yaml, test/lab/openapi/lab-api.remote-ref.yaml, test/lab/openapi/lab-api.swagger2.yaml, … |
| I5.T4 | C | T3 | Scorecard safety gates and baseline runner | test/lab/scorecard/main.go, test/lab/run_baseline.py |
| I5.T5 | A | I4.T5, I4.T6 | Embedded frontend asset refresh (deliberate) | web/static/app.js, web/static/style.css, web/static/index.html |
| I5.T6 | D | I1.T19, I2.T9, I2.T10, I3.T7, I3.T10, I3.T11, I4.T2, I4.T7, T1, T4, T5 | Full regression, plan status flip, validation record | docs/superpowers/plans/2026-10-02-web-api-workflow.md, runtime/validation.md |

## 6. Explicit deferrals / documented gaps

- Schemathesis API fuzzing (section 2.1). ZAP, Nuclei and native checks cover
  the first release.
- DefectDojo integration (2.1). Xalgorix findings and reports come first.
- Browser SSO/MFA automation (2.3) is unsupported. A supplied valid session may
  be used when verification succeeds.
- Pinned headless authenticated Katana (2.3). The standard-engine fallback is
  preserved, and missing browser-executed discovery is surfaced as a run
  limitation.
- Headless Nuclei templates. Browser sub-requests cannot be scope-checked, so
  these templates are excluded by the default policy and reported as a limitation
  (I1.T13).
- Wapiti outside a test environment. Its form submission and SSRF modules
  conflict with the low-impact policy, so it is restricted with a visible gap
  (I1.T14). Nikto is restricted whenever exclusions are configured.
- GraphQL, SOAP, gRPC, WebSocket, broad fuzzing and inferred business workflows
  (2.3) remain documented gaps.
- SQLMap automatic selection (2.2). It stays explicit-approval-only, and no
  automatic path is added.
- No production override for the gau/waybackurls provider endpoint. The lab
  uses fake binaries through the configured tool paths instead.
- Live EPSS/KEV risk feeds and automatic `VERIFIED` finding status are out of
  scope. The findings engine stays the single source, and technology detections
  stay observations.
- Multi-user roles and a tamper-proof audit are not in this spec.
- Server/cloud/Kubernetes/code/monitoring workflow expansion (2.1). The first
  release covers one application and its approved API origins only.

## 7. Verification commands

Run focused tests per task, then the full gates at every group and increment
boundary, after merging that group's worktrees. On macOS use `CGO_ENABLED=0` and
exclude the environmental `internal/sandbox` and `internal/resources` failures.
Python always runs with `PYTHONDONTWRITEBYTECODE=1`, because tracked `.pyc` files
exist.

```sh
# Focused (foundation / discovery / API / web)
CGO_ENABLED=0 go test ./internal/assessment/... ./internal/scanner/... ./internal/web/... ./internal/credentials/... ./internal/storage/... ./internal/ratelimit/...

# Full Go gates (exclude environmental macOS failures)
CGO_ENABLED=0 go test $(go list ./... | grep -v '/internal/sandbox' | grep -v '/internal/resources') -timeout 15m
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go vet ./...
gofmt -l internal cmd test

# WebUI (no in-tree build; typecheck + scratch build)
(cd webui && ./node_modules/.bin/tsc -p tsconfig.app.json --noEmit && ./node_modules/.bin/tsc -p tsconfig.node.json --noEmit)
(cd webui && ./node_modules/.bin/vite build --outDir /tmp/xalgorix-static --emptyOutDir)

# Runtime manifest + offline smoke (lock-aware)
PYTHONDONTWRITEBYTECODE=1 python3 runtime/test_content_manifest.py
docker build . -t xalgorix:local
docker run --rm --network none --entrypoint python3 xalgorix:local /usr/local/share/xalgorix/smoke-test.py

# Linux Docker lab acceptance + whitespace
docker compose -f test/lab/compose.yaml build
PYTHONDONTWRITEBYTECODE=1 python3 test/lab/test_run_baseline.py
PYTHONDONTWRITEBYTECODE=1 python3 test/lab/run_baseline.py
git diff --check
git status --short   # no stray .pyc / tsbuildinfo / ignored-fixture surprises

# Embedded asset refresh (final, deliberate — I5.T5)
cp /tmp/xalgorix-static/app.js /tmp/xalgorix-static/style.css /tmp/xalgorix-static/index.html internal/web/static/
node --check internal/web/static/app.js
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./internal/web/...
```

Release only after scope isolation, credential handling, method restrictions and
truthful coverage pass. Report measured detection results separately: successful
tool execution is not proof of vulnerability coverage.

## 8. Critique resolution log (revision 2)

Each critique item was checked against the code at `2052bca` before it was
applied. Task IDs refer to this revision.

Mapping from revision-1 IDs: I1.T4 was split into I1.T4 and I1.T18. I1.T9 was
split into I1.T9 and I1.T19. I1.T10 was split into I1.T11, I1.T12, I1.T13 and
I1.T17. New in I1: I1.T10 (schedules), I1.T14 (adapter policy), I1.T15 (ZAP
scope), I1.T16 (SPA fallback). I2.T7 became I2.T8 and I2.T9. New in I2: I2.T7
(TLS services) and I2.T10 (runtime pins). I3.T5 was split into I3.T6, I3.T7 and
I3.T11. New in I3: I3.T3 (fixture store), I3.T9 (identities), I3.T10 (passive).
I5.T1 and I5.T2 were merged into I5.T1. I5.T3 was split into I5.T2 and I5.T3.

**Coverage lens**

1. Nuclei template policy: applied in I1.T13 (`-pt http`, `-etags`, `-ni -dr` on every path, limitation recorded). It sits in I1 because policy enforcement is foundation work.
2. Wapiti/Dalfox/Nikto constraints: applied in I1.T14, with the planner showing restrictions at preview in I1.T18.
3. No write replay: applied with the write journal (I1.T8) and the resume gate (I1.T17), tested by TestResumeNeverReplaysInterruptedWrite.
4. Executor for approved writes: applied in I3.T7, the only sender, with exactly-once delivery, journaling and cleanup. ZAP and Nuclei never receive writes (I3.T4/T5/T11).
5. Two identities, expectations and fixture store: applied in I3.T1 (model), I3.T3 (store), I3.T9 (lifting the one-session restriction) and I4.T5 (UI).
6. Producers for failed/expired: applied in I1.T3 (failed), I1.T5 (`Run.AuthState`), I1.T15 (ZAP expiry) and I1.T17 (executor expiry). I4.T1 depends on these tasks.
7. Typed subfinder: applied in I2.T4 (builder with `-duc`) and I2.T9 (stage wiring).
8. Assessment-wide budget: applied. `AssessmentBudget` (I1.T5/T11) is one deadline, one endpoint cap and one limiter. Per-tool retry/timeout/concurrency bounds come from I1.T12–T15. Native clients use the shared limiter (I2.T3, I3.T6), and SPA validation is bounded (I1.T16).
9. Katana redirects: applied in I1.T12 (redirects disabled for authenticated crawls, flag verified against v1.7.0), with a lab gate in I5.T4.
10. Execution-time scope guard: applied through the `Config.ScopeGuard` hook (I1.T5, wired in I1.T9), used by I2.T2 (rebinding), I2.T3, I3.T6 and I1.T16. ApprovedOrigins are checked at preview and start (I1.T7).
11. Tool versions in the fingerprint: partly rejected. Spec section 4 explicitly requires fingerprinting tool/template versions, so they stay in. Applied: versions come only from the content manifest, never from executing binaries; per-stage versions are kept in the manifest; schedule drift is visible (I1.T10); the contradictory compatibility claim is fixed (section 4).
12. Stage input checksums, classifier bump, atomic writes: applied in I1.T8 (`StageInputChecksum` with upstream outputs), I1.T17, I1.T6 (classifier 1->2) and I1.T7 (`WriteAtomic`).
13. Passive stage: applied with the ZAP passive variant (I3.T5) and local response checks (I3.T10).
14. Discovery provider selections: applied in I1.T1 (model/validation), I1.T4 (auto-mode selection without custom demotion), I2.T9 and I4.T4/T5.
15. Manual seeds: applied in I1.T1, I2.T8 (`MergeManualSeeds`) and I4.T5.
16. Legacy TargetAuth: applied in I1.T19. It is configured but unverifiable, so authenticated jobs are skipped with GapPrerequisiteFailed. The deltas are documented in I4.T7.
17. Refresh for nuclei/katana and the re-login limit: applied in I1.T3 (bounded count) and I1.T17 (per-target expired state, post-run re-verification).
18. testssl per TLS service: applied in I2.T7.
19. Redaction: applied in I3.T6/T7 (both identities' secrets in `req.Secrets`) and I2.T8 (query values and bodies stored by reference).
20. Lab historical stub: partly rejected. A proxy/endpoint override in production code is not added, to avoid a new outbound-redirection setting. Applied: fake gau/waybackurls binaries through the configured paths (I5.T3) and a credential gate (I5.T4).
21. Promotion before executors exist: applied. I1.T4 adds no jobs, and promotion happens in I1.T18 and I2.T9.
22. Coverage state and batch_completed: applied with the new gap kinds (I1.T5), `batch_completed` (I1.T6) and a structured state (I4.T1).
23. Amass pinning: initially applied in I2.T10 as v5.1.1, but the adapter used the standalone v4 `-o` contract and v5 requires its engine service. Updated the runtime pin to v4.2.0, verified its `enum -h` exposes the adapter flags, and retained the passive candidate parser. Amass remains required per runtime/README.md.
24. `-duc` in Go builders: applied in I1.T9, I1.T12, I2.T2, I2.T4 and I2.T6 (legacy recon too), and removed from the runtime task. Nuclei already passes `-duc -dut`.
25. PolicySupport/OutputFormat: applied in I1.T4 (field and existing entries) and I2.T1 (new entries).
26. Historical revalidation scope: applied in I2.T3 (`Allows`/`Excluded`/ScopeGuard checked first, shared limiter, no redirects, archived `/logout` never fetched).

**Fidelity lens**

1. Promotion against real availability: applied through stage-executor routing, binary-presence availability, exclusion from completeness, and an integration test through `buildAssessmentPlan` (I1.T18).
2. `NewPipeline.Runners` registration: applied. Tools are registered only in registry.go (`Available:false`), and `HasAssessmentRunner`/`byName` are wired by each adapter's execution task (I2.T7, I2.T9, I3.T6).
3. Empty State, signatures and stamping: applied in I1.T6 (empty means in_scope, wrappers, State stamped at merge).
4. Legacy path differences: applied by splitting into I1.T9 and I1.T19 with an explicit ZAP/spider/rate/scope-kind/resume mapping, the file reference fixed and the configured subfinder path. One part is rejected: the authenticated crawl is not kept for legacy TargetAuth, because it cannot be verified and the spec requires verification before crawling. The public baseline still runs.
5. Gates for failed/expired: applied in I1.T3 (`hasBlockingAuth`, with a test).
6. Parse integration: applied in I2.T1 (`nil,nil` for evidence-only tools), I2.T5 (sslyze parser and rules), I2.T7 (sslyze runner), I2.T8 (httpx observations) and I3.T6 (apichecks).
7. Fixture store and replay: applied in I3.T3 and I1.T8/T17.
8. Dispatch contract and writes kept away from ZAP: applied in I3.T2 (`DispatchRequest`), I3.T4 and I3.T5. ZAP uses `sendRequest` only for HEAD.
9. AssessmentRPS duplicating RateRPS: applied. It is dropped, per-tool concurrency is bounded, and the test runs on the typed path. Write permission is `WritesPermitted` (TestEnvironment + approvals + not Black Box) and ignores the profile, because `AllowStateChanging` is false for both profiles.
10. Fingerprint exec, schedules and the contradictory test: applied (content manifest only, `needs_review`, test scoped to registry v4).
11. Negative control placement: applied. It runs once in `prepareAssessmentAuthentication`, and `verifyHeaderSession` is unchanged (I1.T3).
12. ApprovedOrigin model and helper delegation: applied (`TargetID`/`Origin` fields, delegation assigned per task). One part is rejected: AppScope is not replaced by `scanner.Scope`, because `scanner` imports `assessment` and this would create a cycle. `scanner.Scope` fields are filled from AppScope instead.
13. Katana and ZAP exclusions in I1: applied in I1.T12 and I1.T15.
14. Nuclei policy: applied in I1.T13 (same as coverage 1).
15. Typed subfinder and provider config: applied (same as coverage 7 and 14).
16. Manifest as a parallel gate: applied. The manifest is a derived record, and the reuse key is extended. The write journal deliberately stays a gate, because the spec forbids replaying writes.
17. I4.T3 files, summary and SampleRequest bodies: applied in I4.T3 and I2.T8.
18. Registry metadata: applied (same as coverage 25).
19. Preview guard: applied. `isBlockedTargetForScan` is reused with `allowLoopbackPorts`, and the duplicate runMultiScan loop is removed (I1.T7).
20. Repo hygiene: applied (premise rewritten, `git add -f`/TempDir rule, `-duc` in builders, `PYTHONDONTWRITEBYTECODE`).
21. Amass and dnsx flags: applied in I2.T10/I2.T4 (pin and `-h` verification); Amass is pinned to v4.2.0 because v5.1.1 removed the adapter's `-o` CLI contract and requires a separately managed engine. DNSX includes the random-label wildcard probe (I2.T2).
22. OpenAPI: applied. I3.T8 materializes at preview with no extra fingerprint input, and I3.T2 handles Swagger 2.0 host/basePath/schemes and body/formData parameters.

**Sequencing lens**

1. Split promotion: applied (I1.T4 group B; I1.T18 group G, which owns HasAssessmentRunner, availability, test updates and run stamping, after I1.T7 and I1.T17).
2. I1.T6 file list: applied with wrappers. `AppScopeForTarget` was added to I1.T1.
3. I2.T1 registry plumbing: applied. `NewPipeline.Runners` is untouched, and execution is wired per adapter task.
4. I3 materializer and ZAP in parallel: applied both ways. I3.T2 defines every APIEndpoint field and `DispatchRequest`, I1.T5 adds `Request.AppScope`, and ZAP (I3.T5, group C) runs after the materializer (I3.T4, group B).
5. PlanInput.APIOperations in I3: partly rejected. Hashing materialized operations is redundant, because definition IDs are content hashes and the inputs are already in the hashed config (fidelity 22). planner.go was first bumped to "6" for native checks and later to "7" when operation materialization became executable.
6. I4.T1 and I4.T2 in parallel: applied. I4.T2 moves to group B and gains report_ai.go.
7. client.ts ownership: applied. I4.T4 owns types, client and queries, and scanner-terminal.tsx goes to I4.T6.
8. HostEvidence in scope.go: applied. The fields move to I2.T1, and I2.T6 moves to group B.
9. sslyze/subfinder/httpx execution: applied (I2.T7 for sslyze, I2.T9 for subfinder/httpx). "Typed-path promotion" was dropped from the I2.T6 title.
10. I1.T5 problems: applied. `WritesPermitted` moves to I3.T1, no `AssessmentRPS` means applyDefaults stays untouched, and `Run.AuthState` is added in I1.T5.
11. Auth-state producers: applied in I1.T3, I1.T17 and I1.T15. ZAP expiry moved from I3 to I1.
12. I1.T7 dependency: applied (now depends on I1.T2).
13. I1.T9 split and file reference: applied (I1.T9 in group D, I1.T19 in group H after the executor). The file reference is now deterministic_scan.go.
14. I1.T10 split: applied (I1.T11, I1.T17, I1.T12, I1.T13, I1.T14). The AssessmentRPS division is dropped (fidelity 9).
15. I3.T5 split and identities: applied (I3.T6 read-only checks, I3.T7 writes/authz, I3.T11 targeted validation; identities in I3.T1/I3.T9).
16. RegistryVersion per increment: applied (4/5/6); API operation materialization adds version 7, approved write execution adds version 8, and optional marker/status-contrast authentication adds version 9 to invalidate plans created under older auth verification rules.
17. I2 shippability: applied. The runtime pins move to I2.T10.
18. Parallel tasks in one package: applied (worktree per task, merge-and-test at group boundaries, prefixed helpers; section 1).
19. I5.T1 and I5.T2 coupled: applied, merged into I5.T1.
20. Stale dirty-tree premise: applied (section 1, I5.T1). The tracked `.pyc` files are flagged.
21. I4.T3 files: applied (scanner_handlers.go, scanner_handlers_test.go, deterministic_scan_test.go).
22. I3 signature breaks: applied (`apiEndpointURL` wrapper; assessment_jobs.go added to I3.T4).
23. I3 flat keys: applied in I3.T3, which owns server.go.
24. Group packing: applied (I3.T1 and I3.T2 in group A; I5.T1, I5.T2 and I5.T5 in group A; I4.T7 in group C).
25. Lab split and files: applied (I5.T2 and I5.T3 with the OpenAPI fixtures listed; test_run_baseline.py added to I5.T4).

# Assessment modes and capability-based planning

## 1. Purpose and implementation contract

Date: 2026-09-28. Code inspected at commit `80a24e8`.

This is an implementation plan for the supplied 35-section requirements document. It extends the existing Xalgorix application. It does not claim that the features below already work. This change set is documentation only.

The product will let an operator choose an assessment mode, assessment types, targets, and available resources, then review a backend-generated scanner plan. Existing scanners, saved scans, schedules, cancellation, artifacts, and deterministic reporting remain supported.

Required hierarchy:

```text
Assessment mode establishes allowed access
  -> supplied resources establish available capabilities per target
  -> assessment types establish requested coverage
  -> registry and planner explain eligible scanner variants
  -> accepted plan becomes persisted execution jobs
  -> existing workers execute jobs
  -> normalized findings and coverage feed deterministic reports
```

Assessment mode, requested coverage, discovery behavior, and scan intensity are separate dimensions. `BLACK_BOX` is not another spelling of `single`, `wildcard`, or `web-gentle`.

No AI subsystem is introduced. The current repository intentionally removed AI execution and report generation in recent commits.

## 2. Current architecture discovered in the code

| Area | Current implementation | Integration decision |
|---|---|---|
| Backend | Go 1.26, standard `net/http`, explicit route registration in `internal/web/server.go` | Extend existing handlers and request models |
| Frontend | React 19, TypeScript, Vite, Tailwind, Radix components, React Query, Zustand | Reuse forms, components, query hooks, and navigation |
| Persistence | JSON records and filesystem artifacts; no assessment database or ORM | Version JSON schemas; do not add SQL tables or a database service |
| Scan model | `ScanRequest`, `ScanInstance`, `ScanRecord`, private `scanSession` | Add shared assessment configuration and snapshots |
| Queue | In-process orchestration, persisted `QueueState`, recovery in `queue_state.go` | Persist plan/configuration identity and resume jobs |
| Scheduling | `ScanSchedule`, JSON storage, existing timezone-aware scheduler | Reuse assessment configuration on scheduled runs |
| Engine | `internal/scanner/pipeline.go`: recon, classify, worker pool, source resolution | Execute planner jobs using existing runners |
| Scanner metadata | `Descriptor`, `Catalog()`, `OrderedNames`, per-runner applicability functions | Consolidate into one registry, retaining compatibility projections |
| Live updates | Gorilla WebSocket events and append-only scanner output | Add job/plan identifiers to existing events |
| Findings | `scanner.Finding`, parsers, cross-scanner merge, `reportFinding`, `VulnSummary` | Carry new fields through every conversion |
| Reporting | `internal/web/report_ai.go` now assembles deterministic reports despite its historical filename; PDF generation also uses `internal/reporting` | Extend current reports; no second reporting system |
| Authentication | Configured operator credentials, bcrypt support, in-memory session tokens, cookies, login throttling, CSRF middleware | Reuse authentication and add actor/permission context |
| Authorization | No existing multi-user role model found in the inspected auth flow | Preserve the operator model and introduce a narrow permission hook |
| Secrets | Target headers excluded from persisted scan fields; operator-managed SSH aliases; redaction helpers; atomic private-file utilities | Add target credential storage using encrypted records and opaque references |
| CLI | `cmd/xalgorix/main.go` builds scanner requests and invokes the deterministic pipeline/report path | Use the same validation and planner as the API |

### Existing execution flow

1. `POST /api/scan` validates a `ScanRequest` and scanner names, then saves or starts an instance.
2. `internal/web/orchestrator.go` creates target sessions; wildcard handling can create child scans.
3. `executeDeterministicScanSession` creates a scanner pipeline and forwards request fields.
4. Recon runs Subfinder, httpx, and per-host Nmap. Host evidence drives web/server tracks.
5. The pipeline dispatches Nuclei, ZAP, testssl, OpenVAS, Vuls, and source scanners according to scope and selection.
6. Scanner outputs and checksums are persisted separately from scan JSON; terminal runs are reused during recovery.
7. Parsers normalize native artifacts; findings are merged and converted into JSON/PDF report data and API findings.

### Actual scanner inventory

Active adapters: Subfinder, httpx, Nmap, Nuclei, ZAP, testssl, OpenVAS/GVM, Vuls, Semgrep, Gitleaks, OSV-Scanner, and Trivy.

Masscan, Nikto, and SQLMap appear in historical documentation or comments, but no active deterministic adapters were found. Lynis has no active adapter. These need implementation, parser fixtures, runtime checks, and deployment configuration before being advertised as runnable.

Gitleaks currently uses working-tree scanning with `--no-git`, so a readable local source directory is sufficient. Requiring a Git repository for every Gitleaks run would regress working behavior.

### Existing gaps that this plan must address

- `ScopeApplication` exists, but recon and pipeline fan-out still construct host/source scopes. Exact application URLs are not used consistently for dispatch.
- The source model represents one `source:main` and one artifact. It cannot cleanly represent a repository plus an image plus independent host access.
- `Profile`, `WebScope`, and `APIDefinitionIDs` exist on `ScanRequest`, but are not consistently propagated through saved instances, schedules, queue state, and sessions. No session constructor assigning `profile` was found.
- Web endpoint/time/browser defaults are assigned into configuration without complete enforcement. They must not be described as implemented safety guarantees.
- The heavy-worker semaphore is local to one pipeline invocation; the comment describing global exclusivity overstates its actual scope.
- ZAP uses a shared daemon, header replacer rules, classic crawling, and an active scan with `inScopeOnly=false`. Authenticated session verification and form login are absent.
- GVM service credentials authenticate Xalgorix to Greenbone; they are not credentials for logging into the target host.
- OpenAPI parsing enumerates methods but does not resolve required parameter values. Remote-reference rejection is a raw-text substring check and misses alternate formatting. Map iteration also makes output order unstable.
- Finding fingerprints include title and scanner, and are computed before source-path normalization. They are not suitable as stable cross-scanner correlation keys.
- Host-level CVE merging can collapse separate services or endpoints. Frontend deduplication lowercases whole URLs, losing case-sensitive path distinctions.
- Confidence/fingerprint metadata is not carried through the report and `VulnSummary` projections.
- Some documentation and comments describe removed agent/AI functionality. Treat active code as authoritative.

## 3. Scope and delivery defaults

Implement all three modes and all eleven assessment type identifiers. Deliver executable coverage for Network, Web Application, API, Source Code, Dependencies, Container, Host, and IaC using current and planned adapters.

Cloud and Kubernetes types remain visible with explicit unsupported-adapter reasons until a real adapter exists. Compliance means a named implemented benchmark, initially Lynis host audit coverage; it does not claim certification or general regulatory compliance. If no requested type has a runnable job, save/preview is permitted but start is rejected.

New integrations in this plan: Masscan, Nikto, SQLMap, and Lynis. Prowler, Kubescape, Checkov, Syft, Grype, and ScoutSuite remain extension examples rather than silently expanding the implementation scope.

Default deployment remains one self-hosted service with the existing workers. No distributed queue, SaaS tenancy, or new database is required. Production web testing retains the gentle profile; intrusive scanner selection requires explicit opt-in independent of assessment mode.

## 4. Typed domain model

Add a small `internal/assessment` package for shared types, normalization, capability evidence, and policy. It must not import `internal/web` or scanner command implementations. Scanner metadata and planning remain in `internal/scanner`, importing these shared types.

### Public enum values

- Mode: `BLACK_BOX`, `GRAY_BOX`, `WHITE_BOX`.
- Types: `NETWORK`, `WEB_APPLICATION`, `API`, `SOURCE_CODE`, `DEPENDENCIES`, `CONTAINER`, `HOST`, `CLOUD`, `KUBERNETES`, `INFRASTRUCTURE_AS_CODE`, `COMPLIANCE`.
- Target kinds: `DOMAIN`, `URL`, `IP`, `CIDR`, `REPOSITORY`, `LOCAL_SOURCE_PATH`, `DOCKER_IMAGE`, `HOST`, `CLOUD_ACCOUNT`, `KUBERNETES_CLUSTER`, and `SBOM` to preserve existing support.
- Capabilities: the requested network, web, authenticated-web, API, schema, source, Git, dependency, image, host, SSH, Windows, cloud, Kubernetes, and IaC capabilities; add `SBOM` for existing artifact behavior.

Use typed Go strings with validation and TypeScript literal unions. Wire names follow the existing snake_case convention: `assessment_mode`, `assessment_types`, `assessment_targets`, `access`, and `scanner_selection`. Uppercase enum values are stable identifiers; display labels are independent.

### Shared structures

- `AssessmentConfig`: mode, types, target/resource records, access bindings, scope policy, profile, scanner overrides, and required scanner variants.
- `Target`: opaque ID, kind, value, optional repository branch, optional related-target ID. URLs retain scheme, port, path case, and entry path.
- `AccessBinding`: target IDs, access kind, credential reference, verification configuration, and optional approved API operations. It never contains resolved secrets in response DTOs.
- `CapabilityEvidence`: capability, target/resource ID, state (`declared`, `available`, `verified`, `unavailable`), provenance, and reason.
- `AssessmentSnapshot`: normalized configuration, derived capabilities, registry version, plan fingerprint, and redacted access summary.
- `PlanJob`: stable job ID, scanner ID, variant, scope ID, dependencies, execution mode, selection decision, reason code, and resource references.

Keep execution lifecycle statuses as the current lowercase wire strings. Add `queued` as a nonterminal state; retain `running`, `completed`, `failed`, `skipped`, `not_applicable`, and `cancelled`. Do not create a conflicting uppercase lifecycle enum on the wire.

## 5. Mode policy and capability derivation

Modes determine allowed access, not scanner lists. Capabilities are derived per target and resource; never union credentials across unrelated targets.

| Mode | Allowed inputs | Validation |
|---|---|---|
| Black Box | Network/web/API targets and public schema/documentation | Reject credential bindings, internal source/image resources, and internal access references; suggest the appropriate mode |
| Gray Box | External targets, schemas, app credentials, limited host access and configuration | Permit supplied partial access; source trees, container images, and full IaC inputs require White Box in this release |
| White Box | All supported resource kinds | Does not create capabilities for missing resources or unsupported adapters |

Derivation rules:

1. A normalized host/IP/CIDR/domain establishes network scope, not verified reachability.
2. An HTTP(S) URL establishes a candidate web target. A domain may produce conditional web discovery jobs; a bare IP does not prove a live web service.
3. API type plus an API base target establishes API access; a validated schema adds API schema capability.
4. Resolvable app credential references establish available authenticated access. A successful verification probe establishes verified access. Reports distinguish these states.
5. A readable local source directory or prepared repository checkout establishes source access. A declared remote repository makes source jobs conditional until preparation succeeds.
6. Manifest and IaC capabilities require bounded inspection of prepared files; neither follows automatically from the word repository.
7. An image reference makes an image job conditional until the runtime can access/pull it; pin its resolved digest in the run snapshot.
8. SSH aliases and credential bindings apply only to their named host targets. Successful connection checks verify access; they do not authorize scanning the scanner server itself.
9. Cloud/Windows/Kubernetes references can be represented, but unsupported worker capabilities must remain visibly unavailable.

A missing source resource produces `not_applicable`. A supplied repository that fails to clone produces a failed preparation job and dependent jobs skipped with a dependency-failure reason. Do not misreport operational failure as missing access.

## 6. Registry and scanner variants

Extend the existing registry rather than building an unrelated list. Derive `Catalog()`, scanner name validation, UI metadata, and planner rules from the same definitions. Retain stable legacy scanner IDs such as `osv`, `openvas`, and `testssl`.

Each definition contains ID, label, category, supported assessment types, target kinds, variant definitions, required-all/required-any capabilities, optional capabilities, auth support, runtime availability probe, risk class, default selection policy, weight, adapter, and parser association.

| Scanner/variant | Types | Requirements and selection |
|---|---|---|
| Subfinder discovery | Network/Web/API discovery | Domain plus explicit subdomain discovery permission; never unconditional |
| httpx discovery | Network/Web/API | Network or web target; preserve approved origins/ports |
| Nmap service discovery | Network/Host | Approved host/IP/CIDR; Host includes service inventory |
| Masscan discovery | Network | IP/CIDR, available binary/runtime privileges; optional fast discovery with bounded rate |
| OpenVAS unauthenticated | Network/Host | Approved host scope plus healthy GMP backend |
| OpenVAS credentialed | Network/Host | Supported target credential binding and verified implementation; never use GMP admin credentials as target credentials |
| Nuclei web | Web/API | Web access; origin-bound auth optional; curated profile content |
| ZAP web/API | Web/API | Web access; optional verified auth and API schema; explicit context |
| testssl TLS | Web/Network | TLS endpoint; one job per relevant origin/port |
| Nikto web | Web | Web access; optional advanced selection, profile limits |
| SQLMap detection | Web/API | Approved parameterized request, explicit opt-in, compatible profile; no destructive flags |
| Semgrep source | Source Code | Prepared source tree |
| Gitleaks files | Source Code | Prepared source tree; preserve existing non-Git behavior |
| OSV dependencies/SBOM | Dependencies | Supported discovered manifest or supported SBOM input |
| Trivy filesystem dependencies | Dependencies | Prepared source with applicable manifests |
| Trivy image | Container | Image resource; image-specific command and provenance |
| Trivy IaC | IaC | Prepared supported IaC files; misconfiguration scanner variant |
| Trivy SBOM | Dependencies | Supported SBOM resource |
| Vuls host | Host | Target-bound operator SSH alias; retain current adapter |
| Lynis host audit | Host/Compliance | Target-bound SSH access, installed Lynis, and named audit profile |

Keep any existing Trivy secret/license behavior as explicit variant options or compatibility behavior; do not silently discard it when adding type-specific selection.

Definition eligibility and runtime availability are separate. A relevant scanner with a missing binary is applicable but unavailable. A scanner without source input is not applicable. An operator-disabled applicable scanner is skipped. Every decision retains a stable reason code and readable explanation.

## 7. Deterministic planner algorithm

Implement `PlanAssessment` in `internal/scanner`, using pure inputs for resource evidence and runtime health. I/O happens in a preparation service, not inside conditional scanner-selection branches.

1. Normalize enums, targets, selection, discovery policy, and access bindings.
2. Validate mode/access compatibility and target boundaries.
3. Derive declared/available capabilities and preparation requirements.
4. Match requested assessment types against registry variants.
5. Evaluate target kinds, capability requirements, optional access, installed adapters, and profile restrictions.
6. Produce selected, optional, conditional, unavailable, and non-applicable decisions with reasons.
7. Build dependency jobs for repository preparation, manifest discovery, network discovery, authentication checks, and schema preparation.
8. Deduplicate shared prerequisites and emit stable sorted job IDs and a plan fingerprint.
9. Return per-type coverage, recommended/applicable/non-applicable scanners, warnings, blocking errors, and planned jobs.

Preview must not clone arbitrary repositories, log into targets, run scans, or follow uploaded remote references. It may inspect already uploaded local resources and cached service health. It honestly returns conditional decisions for resources requiring execution-time preparation.

At start, regenerate and validate the plan on the server. Never accept browser-supplied capabilities as evidence. A supplied preview fingerprint that no longer matches returns HTTP 409 with a refreshed plan; the UI requests a new review. An unavailable explicitly required scanner is a blocking error. An ordinary optional scanner remains an explained coverage gap.

New requests use `scanner_selection.mode = auto | custom`; omitted means auto, while custom requires a nonempty validated variant list. Keep legacy `scanners: []` meaning all legacy scanners. Reject conflicting old and new selection fields.

Preparation can only enable jobs already conditional in the accepted plan and only within its target scope. Persist preparation evidence and the resolved job graph. Do not use newly discovered unrelated services to broaden authorization.

## 8. Execution, scope, and recovery

Refactor task creation around `PlanJob`; reuse runner command construction, output capture, cancellation, checksums, and parsers. Legacy requests are translated into a compatibility plan that preserves historical scanner selection.

- Replace the unconditional recon phase for new assessments with selected preparation jobs. Source-only assessments perform no network recon.
- Support multiple source, image, application, and host scopes. Derive filesystem paths from opaque IDs/hashes rather than lossy target sanitization.
- Web dispatch receives the exact application URL. Network dispatch receives a normalized host or bounded CIDR member.
- Extend job identity to `(scope, scanner, variant)` and persist attempt IDs. Existing `(scope, scanner)` records use a legacy variant.
- Implement a shared scheduler resource gate across instances and a service lease per ZAP backend. Use context-aware acquisition so cancelled queued work does not wait indefinitely.
- Fresh ZAP contexts/sessions require a dedicated managed daemon. Scope replacers, crawling, active scan, and cleanup; a cleanup failure makes that worker unavailable until reset.
- Validate discovery output, redirects, and resolved destinations against explicit scope. Domain discovery stays within approved boundaries. CIDR processing is bounded and incremental, not an unbounded in-memory expansion.
- Bind auth to origin and access scope. Local source roots, SSH aliases, and server-managed secret references require path/target validation.
- Enforce configured timeout, endpoint, and per-origin request limits through adapters. If an adapter cannot enforce a selected profile constraint, declare that variant unavailable for the profile.
- Keep scanner lifecycle separate from assessment coverage: a completed job can have partial coverage; an assessment with tool failures must not look fully tested.

Persist normalized configuration, registry/content revisions, resource revisions/digests, and plan fingerprint. Resume reuses a completed job only when job identity, relevant configuration, and checksums match. Source checkout commits and image digests are immutable for that run. Changed input creates a new run; old evidence remains intact.

## 9. Credentials and authenticated testing

There is no general target secret vault in the inspected code. File permissions and password hashes are not encryption for reusable target credentials.

Add a focused credentials service using AES-256-GCM encrypted records and `internal/storage.WriteAtomic`. Obtain the 32-byte master key from an operator-mounted file outside the data directory. Each record has a key ID, random nonce, version, typed payload, and authenticated metadata. Require the key to save reusable secrets; fail clearly rather than persist plaintext when missing.

Use opaque credential IDs in scans, schedules, plans, audit events, and responses. Credential create/update is write-only for secret values. List/read returns type, label, allowed target bindings, timestamps, and configured state only. Do not place raw secrets in React Query caches or persistent browser storage.

Support app headers/cookies/bearer/API keys, form-login credentials, repository credentials, and SSH references. Preserve operator-managed SSH aliases as the simplest host option. Windows/cloud/Kubernetes inputs use typed references but remain unsupported for execution until their adapters exist.

For forms, store login URL, field names, CSRF extraction configuration, verification URL, and expected marker separately from credential values. Verify the session before authenticated scanning, detect expiration, retry login once, then record failed authenticated coverage. Implement origin-bound cookies/headers and backend-specific authenticated contexts. Supplying a password alone never earns an Authenticated report label.

Prefer private temporary scanner configuration files, pipes, or supported credential mechanisms over process arguments. Include resolved, encoded, and session-derived tokens in redaction. Validate raw logs, native artifacts, generated reports, WebSocket events, and error paths. Remove temporary credentials on success, cancellation, and failure.

Backups include encrypted data; document separate master-key backup and rotation. A missing or rotated-away key blocks credential-dependent jobs after restart without silently falling back to anonymous testing.

## 10. API changes and persistence migration

### API surface

Reuse current scan identifiers and endpoints. New UI wording says Assessment; APIs continue using scan naming.

| Endpoint | Change |
|---|---|
| `POST /api/scan` | Accept assessment configuration, selection, optional accepted plan fingerprint; validate/replan before start |
| `POST /api/scans/plan` | Pure planning preview with redacted capability evidence, coverage, reasons, and fingerprint |
| `GET /api/scanners/registry` | Registry metadata and supported type/mode labels |
| `GET /api/scanners/status` | Keep current shape; add variant availability, version, and capability details |
| `GET /api/scans`, `/api/scans/:id`, `/api/instances` | Add assessment summary and coverage state |
| Existing instance start/stop/restart and queue routes | Preserve assessment configuration and accepted plan through actions |
| `GET /api/scans/:id/plan` | Persisted accepted/resolved plan and decisions |
| `GET /api/scans/:id/scopes` | Extend existing scope response with variants/jobs/reasons |
| `GET /api/scans/:id/coverage` | Requested versus tested types, targets, access, and limitations |
| Existing findings/report routes | Add canonical confidence, correlation, and assessment metadata |
| Existing schedule routes | Persist shared assessment configuration; preview and revalidate each trigger |
| `POST /api/api-definitions` | Bounded JSON/YAML upload, structural validation, immutable opaque ID |
| `/api/credentials` and `/api/credentials/:id` | Create/list, metadata read, replace, delete under existing auth/CSRF protections |
| `GET /api/scans/:id/audit` | Redacted assessment lifecycle events |

Register exact `/api/scans/plan` before relying on the existing generic scan-ID dispatcher. Extend method, CSRF, and route-wiring tests. Use 400 for malformed/unknown values, 422 for unstartable valid configurations, 409 for stale plans or active-run conflicts, and 503 for unavailable required runtime dependencies.

### Example new request

```json
{
  "name": "Application assessment",
  "assessment_mode": "GRAY_BOX",
  "assessment_types": ["WEB_APPLICATION", "API"],
  "assessment_targets": [
    {"id": "app", "type": "URL", "value": "https://app.example.test:8443/Portal/"}
  ],
  "access": [
    {"target_ids": ["app"], "kind": "APPLICATION_HEADERS", "credential_id": "cred_example"}
  ],
  "api_definition_ids": ["definition_example"],
  "profile": "web-gentle",
  "scanner_selection": {"mode": "auto"},
  "plan_fingerprint": "sha256:example"
}
```

Credential references and schema uploads are explicitly associated with target IDs in the canonical normalized model. Reject ambiguous associations in multi-target requests.

For the CLI, add `--assessment-mode`, repeatable `--assessment-type`, `--assessment-config`, and `--plan`. The configuration file uses the same typed assessment shape and credential references as the API. `--plan` prints the redacted preview without executing target operations. Preserve existing `--target`, `--source`, `--scanners`, and SSH-alias options through the compatibility adapter; reject conflicting canonical and legacy inputs instead of choosing silently. API schema file input is prepared locally under the same bounds as uploads.

### JSON migration

Use schema version 3 for newly written assessment scan/report records. Add versioning to queue/schedule records where absent. Reuse existing directories and private atomic writes; add protected `_credentials`, `_api_definitions`, and audit storage entries to retention/deletion exclusions.

Read v1/v2 records through adapters. Display missing assessment mode as Legacy/unspecified in presentation metadata; do not assign `BLACK_BOX` to historical source or credentialed scans. `LEGACY` is not a selectable mode or a fourth business mode.

Old records and PDFs remain unchanged. New runs cloned from legacy settings ask for a mode in the UI; old API clients continue via explicit compatibility translation. Reports regenerated from historical runs retain original scope and evidence semantics.

Thread the shared configuration through every request-to-instance-to-queue-to-session and schedule-to-request conversion. Add round-trip tests for all copies; profile fields currently demonstrate why this matters.

No SQL migrations are needed. Provide backup and rollback instructions: retain the previous binary and read-only old records; do not resume new-schema work with an older binary. A schema migration helper, if required for indexes, is idempotent and never modifies native artifacts.

## 11. New adapter and input preparation work

### OpenAPI

Replace substring checks with recursive structural reference validation. Support Swagger 2 and OpenAPI 3.0/3.1; resolve internal JSON pointers with cycle/depth limits and reject remote refs in the first release. Normalize JSON/YAML to one typed representation and sort operations.

Validate explicit base-origin mapping, parameters, examples/defaults, request bodies, and required operator overrides. Operations with unresolved values remain untested with reasons. Import eligible operations into the ZAP context. Fetching a user-supplied schema URL is a separate bounded scoped preparation action; preview never performs the fetch. State-changing operations require explicit operation selection.

### New tools

- Masscan: bounded IP/CIDR discovery, conservative configurable packet rate, machine-readable output, target containment, required-capability checks, cancellation, and service handoff to Nmap. Applicable does not imply selected by default.
- Nikto: version-pinned structured output, bounded scan settings, scope/auth handling, and parser fixtures. Expose as an advanced optional web scanner.
- SQLMap: only an explicitly approved request/parameter; detection-only policy, bounded requests/time, no dumping, shell access, file writes, or destructive options. Mark unavailable when the selected gentle policy cannot be enforced.
- Lynis: run an installed audit tool on a specifically bound SSH target, collect its report format, normalize findings, and document non-root audit limitations. Never substitute a scan of the Xalgorix host for unavailable remote access.
- OpenVAS target credentials: attach a supported credential reference to the target through GMP, track external credential/task IDs for cleanup, and prove credentialed execution using returned evidence before labeling it credentialed.

Each adapter uses the existing execution/output model, explicit arguments, configurable executable/service paths, parser fixtures, and health checks. A package installed in Docker is not proof that the integration works.

## 12. Findings, correlation, confidence, and prioritization

Extend the canonical finding and every projection with stable identity, asset/scope identity, affected locations, method/parameter, host/port/protocol, CVE list, CVSS vector/version, native confidence, normalized confidence, remediation, references, evidence sources, and first/last seen timestamps.

Separate an observation ID (scanner-native record identity) from a correlation fingerprint. Compute fingerprints after canonical path normalization. For web issues, include origin, case-preserved path, method, parameter, and vulnerability identity. For dependencies, include package ecosystem/name/version and artifact/file context. For host CVEs, include service/component identity when available. Titles, severity, scan directory paths, and ordering must not determine stable identity.

Matching CVEs on unrelated assets or a repository and a running host are not automatically one finding. Correlate only compatible asset/location identities; otherwise keep a related-CVE link. Preserve every native source reference and rating disagreement.

Normalize confidence to `LOW`, `MEDIUM`, or `HIGH` using explicit scanner-specific mappings and evidence rules. Preserve the raw scanner value. Multiple independent matching observations may raise confidence; authentication alone does not prove a vulnerability. `VERIFIED` requires a separate validation record with method and evidence, and is never assigned automatically by this implementation.

Add nullable risk context for EPSS score/percentile, KEV membership, feed provenance/time, asset criticality, exposure, and authentication requirement. Unknown values stay unknown. No live feed integration or fabricated risk data is needed for this release. Initial sorting uses observed severity plus explicit asset metadata and displays the basis.

Update backend/frontend deduplication to consume canonical IDs. Preserve legacy display fallback for old findings. Track new, recurring, and no-longer-observed states; only claim resolved where comparable successful coverage includes the affected location. Failed or missing retests leave status unknown.

## 13. Frontend flow

Keep `/scans/new` and current design components. Change the label to New Assessment and use six compact sections:

1. Mode cards: Black Box, Gray Box, White Box, with the supplied beginner descriptions.
2. Assessment type checkboxes with supported/unsupported explanations from the registry.
3. Typed targets and resources: network inputs, URLs, repository/branch, image, host, and schema upload.
4. Available access appropriate to the mode, using credential references and optional verified-login setup.
5. Server-generated plan grouped by category, showing selected/optional/conditional/unavailable/non-applicable decisions and explanations.
6. Review and Start, including mode, types, scope, capabilities, profile, access summary, and coverage limitations.

Advanced Scanner Selection expands the planner's eligible options. Client-side validation is convenience only. Changes to mode/types/resources invalidate the preview; Start requires a current plan. Debounce preview requests and cancel stale requests so old responses cannot overwrite a newer form.

Extract a reusable assessment form/configuration component for New Scan, saved scans, and schedules. Update the alternative New Scan dialog as well as the page so no entry point bypasses planning.

On detail/list/instance pages, show mode/types, scanner variants, per-scope jobs, and coverage state. Show not applicable as a neutral status with a reason, unavailable as a configuration issue, and failed only for attempted operations. Display configured versus verified authentication distinctly.

Findings show affected locations, sources, confidence basis, and remediation. Reports retain download and regeneration flows. Old scans show a Legacy label rather than guessed mode.

## 14. Reports, audit, and permission integration

Extend deterministic JSON/PDF reports with assessment mode/types, target scope, resource/access kinds, scanner selection reasons, intended and observed execution modes, verified access state, partial coverage, correlations, remediation, and limitations.

Generate limitations from actual coverage. White Box without source input must say source analysis was not performed. Black Box reports state that internal code and credentialed host checks were outside supplied access. Source-only reports do not imply web runtime testing.

Audit events include actor, assessment/instance ID, mode/types, sanitized target summary, registry/plan version, selection, start/end, preparation failures, job transitions, cancellation, and deletion. Never serialize entire request structs into audit records. Keep bounded append-only structured events separate from live console output; record that this is not tamper-proof storage.

Use existing session authentication and CSRF. Attach the configured operator identity to request context; auth-disabled local mode uses `local-operator`. Scheduled execution records both schedule owner and scheduler actor; CLI uses an explicit local actor.

Introduce a centralized permission check with the requested assessment/scanner/credential action names. Map the existing operator to all supported actions. No new role management UI or second identity store is required; future multi-user role mapping plugs into this check.

## 15. Implementation phases and commit sequence

Each row is a logical tested commit, or a tightly related series if review size requires splitting. Application changes begin on a dedicated implementation branch. Commit failing experiments only as work-in-progress outside the delivery sequence.

| # | Commit topic | Deliverable and acceptance |
|---|---|---|
| 1 | `test(assessment): capture legacy execution contracts` | Fixtures for v1/v2 records, saved scans, schedules, queue recovery, current scanner outputs; baseline checks recorded |
| 2 | `feat(assessment): define modes types resources and access policy` | Typed shared model, mode/resource validation, target normalization, per-target capability evidence |
| 3 | `refactor(scanner): centralize registry and variant metadata` | Existing catalog/name validation derived from registry; all current tools preserved |
| 4 | `feat(scanner): add deterministic capability planner` | Pure planner, stable reasons/jobs/fingerprint, preview examples and no-I/O contract tests |
| 5 | `feat(storage): persist assessment snapshots and legacy adapters` | Schema 3, atomic writes, all saved/queued/scheduled field round trips, old readers |
| 6 | `feat(credentials): add encrypted target credential references` | Encrypted vault, target binding, redaction and restart/rotation behavior |
| 7 | `feat(api): expose assessment planning and registry endpoints` | Existing create/list/detail extensions, preview, typed errors, middleware/CSRF coverage |
| 8 | `feat(scanner): execute scoped variant jobs from plans` | Exact URLs, multiple resources, selected recon, stable job paths, cancellation and checksum-aware resume |
| 9 | `fix(scanner): enforce shared worker limits and ZAP isolation` | Across-instance gates, managed ZAP lease/context, cleanup/quarantine, scope enforcement |
| 10 | `feat(scanner): verify and maintain application authentication` | Headers and form sessions, verification, bounded reauthentication, authenticated reporting evidence |
| 11 | `feat(scanner): prepare API schemas and resource capabilities` | Safe OpenAPI handling, ZAP import, manifest/IaC discovery, repository branch/commit and image digest |
| 12 | `feat(scanner): add Masscan and Nikto adapters` | Structured output, parsers, health and runtime config, safe bounded execution tests |
| 13 | `feat(scanner): add opt-in SQLMap detection jobs` | Approved parameter jobs, policy enforcement, limits, parser and negative safety tests |
| 14 | `feat(scanner): add Lynis and credentialed host variants` | Remote Lynis, preserved Vuls, supported GMP target credentials, verified mode evidence |
| 15 | `feat(findings): preserve identities confidence and correlation` | Stable observation/correlation IDs, all projection fields, conservative correlation and nullable risk context |
| 16 | `feat(webui): add assessment creation and plan review` | Shared form for page/dialog/schedules, mode/type/resource inputs, backend plan review |
| 17 | `feat(webui): show assessment coverage and scanner decisions` | Status/list/detail/findings presentation; legacy display and partial coverage |
| 18 | `feat(reporting): add assessment scope access and limitations` | JSON/PDF coverage, sources, remediation, audit events, actor/permission hooks |
| 19 | `test(release): validate assessment workflows and migration` | Linux suite, frontend/e2e tests, container integration evidence, documentation and release checklist |

Dependencies: execution changes require registry/planner and persistence; authenticated execution requires credential storage and ZAP isolation; UI start depends on API validation; release requires integrated job/report testing. Do not ship a UI claiming adapter support before that adapter's tests and health checks pass.

## 16. Planned code touchpoints

New modules (proposed):

- `internal/assessment/{types,validate,capabilities,scope}.go` and focused tests.
- `internal/scanner/{registry,planner,preparation,job,auth,capability_probe}.go` and tests, extending existing `descriptor.go`, `scope.go`, and `pipeline.go`.
- `internal/credentials/{store,redact}.go` and tests, reusing storage primitives.
- Scanner adapters/parsers for Masscan, Nikto, SQLMap, and Lynis under `internal/scanner`.
- `internal/web/{assessment_handlers,credential_handlers,assessment_audit}.go` and handler/compatibility tests.
- Shared assessment form, plan preview, capability/reason components under `webui/src/components` and frontend tests.

Existing groups to extend:

- Request/state propagation: `server.go`, `orchestrator.go`, `queue_state.go`, `scan_session.go`, `scan_record.go`, `deterministic_scan.go`, `scheduler.go`, and `schedules.go`.
- Scanner operations: source/recon/classification, ZAP/GMP, Trivy routing, parsing/merge, output handlers, and CLI config/flags.
- Reporting: deterministic report manifest/projections, scope coverage, PDF generation, and snapshot fixtures.
- UI/API: `webui/src/types/api.ts`, client/query modules, New Scan/dialog, schedules, details/lists/findings, status components, sidebar wording.
- Runtime/docs: executable settings, Docker/Compose, CI, README, architecture, testing checklist, and release notes.

Keep unrelated removals/refactors out. In particular, the historical `report_ai.go` filename does not justify reintroducing AI or rewriting report generation.

## 17. Test and acceptance matrix

### Required planner examples

| Case | Expected result |
|---|---|
| Black Box + Network + IP | Nmap/OpenVAS applicable; Masscan applicable when installed and optional; source/host-auth tools not applicable |
| Black Box + Web + URL | httpx/Nuclei/ZAP applicable; Nikto optional; Semgrep not applicable; no automatic broad port scan |
| Gray Box + Web + app credentials | Auth checks planned; Nuclei/ZAP authenticated only after verification; SQLMap only after parameter approval and opt-in |
| White Box + Source + repository | Prepare checkout; Semgrep/Gitleaks eligible; OSV/Trivy dependencies only when Dependencies requested and manifests found |
| White Box + Host + SSH | Nmap service inventory; Vuls/Lynis eligible; OpenVAS credentialed only where adapter and target credentials are supported |
| Source selected without source | Non-applicable code jobs and explanatory gaps; no crash; start blocked only if no runnable work or required scanner missing |
| White Box + repository + image + URL | Distinct scopes and Trivy variants; no result overwrites or duplicate resume identity |
| Cloud/Kubernetes without adapter | Type remains visible, unsupported reason returned, never a fake completed scan |

The supplied example expecting OSV from Source Code alone conflicts with explicit type-driven coverage. Resolve this by having the UI recommend adding Dependencies when a repository is supplied; the backend must not silently add a type the operator did not request.

### Unit and property tests

- Unknown enums, malformed targets, conflicting legacy/new fields, custom empty selection, required scanner missing.
- No capability inflation from White Box; no target A credentials on target B; declared versus verified resource states.
- Deterministic plan order/fingerprint under reordered equivalent inputs; title-independent finding identity; URL path case retained.
- Every installed adapter has registry metadata/parser coverage; every job has a reason and stable variant ID.
- Scope boundaries: IPv4/IPv6/CIDR, default/explicit ports, path-prefix boundaries, redirect host changes, unrelated discovery, listener protection.
- Ciphertext persistence, tamper rejection, missing key, credential deletion, encoded-secret redaction, API metadata-only reads.
- Malformed/truncated artifacts, all ZAP instances, same CVE on different assets, evidence retention, unrated confidence/unknown risk fields.

### Integration and recovery tests

- Same configuration through API, CLI, save/start, restart, wildcard children, schedule trigger, and process recovery.
- Two concurrent ZAP jobs with different credentials; cancellation while waiting; cleanup failure quarantine.
- Login success/failure, CSRF forms, expired session, reauthentication failure; no anonymous fallback labeled authenticated.
- Repository failure versus genuinely missing source; image plus source; branch pinning; missing manifests; credential reference missing after restart.
- Accepted plan cannot gain unapproved targets/jobs during preparation; stale plan rejected; changed checksum/config blocks reuse.
- Complete report and coverage even with some scanners failed, skipped, or not applicable.
- Real new-tool smoke tests against local fixtures on Linux; no company or third-party production scan is needed for validation.

### Frontend and report tests

- Mode changes clear incompatible selections with an explanation; advanced selection cannot enable invalid tools.
- Preview failures/stale responses, required fields, multi-target bindings, save-only and scheduled configurations.
- Neutral not-applicable display, unavailable versus failed, auth verification labels, legacy records.
- Every canonical field survives parser -> report -> persisted summary -> API -> UI/export.
- PDF/JSON snapshots include mode/types/access kinds and coverage limitations, and contain no seeded secrets.

### Required verification commands

Run focused tests per commit, then full gates at integration/release boundaries:

```sh
CGO_ENABLED=0 go test ./internal/assessment ./internal/scanner ./internal/web ./internal/credentials ./internal/storage ./internal/scopeguard
CGO_ENABLED=0 go test ./... -timeout 10m
CGO_ENABLED=0 go vet ./...
make lint
(cd webui && npm run typecheck && npm run build)
make build
```

Run Go race tests on supported Linux CI with CGO enabled. Add frontend unit/component and browser test scripts because the current package has no test script. Use test doubles for most scanner orchestration tests and pinned real adapters for integration fixtures.

The prior session observed macOS resource tests looping on missing `/proc` files. Reassess that baseline with an explicit timeout; fix platform-specific testability where needed or execute the supported Linux gate. Do not mark a timed-out suite as passing or disable tests to hide a failure. Frontend builds overwrite embedded static assets, so review generated diffs and keep them consistent with source in delivery commits.

Planning inspection did not rerun this entire test matrix and makes no current green-build claim.

## 18. Rollout, acceptance, and implementation handoff

1. Capture legacy fixtures and baseline results before execution changes.
2. Deliver backend preview and persistence first; validate new and compatibility plans in tests.
3. Validate complete execution against local lab targets with every supported mode/type/resource combination.
4. Enable the assessment form when backend execution, credential handling, and plan review are integrated.
5. Roll out to company staging, then operator-selected authorized targets. Deployment and production scanning are separate actions from implementing this plan.

Completion requires functioning mode/type/resource planning from all entry points; reasons for every decision; existing scanner preservation; genuine new adapters where advertised; secret-safe persistence; immutable evidence; no false authenticated/verified/completed claims; backward-compatible history; and successful required checks.

The final implementation handoff must include architecture summary, files changed/added, JSON migration explanation, registry/planner behavior, frontend/API changes, added tests and actual results, external runtime requirements, and explicit unsupported features.

External prerequisites include scanner binaries, a supported dedicated ZAP backend, Greenbone feeds/service, optional Masscan privileges, remote Lynis installation and SSH access, and the credential encryption key. Missing prerequisites must be visible in the plan and coverage.

## 19. Requirements traceability

| Supplied requirement sections | Plan coverage |
|---|---|
| 1, 27, 34 | Architecture inventory, existing gaps, code touchpoints, reuse and typed implementation |
| 2–6, 33 | Domain model, mode policy, target-bound resource/capability derivation |
| 7–10, 21, 26, 32 | Registry, variants, planner, selection/required-scanner semantics, extensibility |
| 11–12, 25, 29–31 | Shared assessment form, plan review, status UX, executable examples |
| 13–14 | JSON schema 3, shared snapshots, legacy adapters and rollback |
| 15–18 | Normalized findings, conservative correlation, confidence and nullable risk context |
| 19 | Deterministic report metadata, access evidence and testing limitations |
| 20 | Extended scan API, planner/registry/credential endpoints, compatibility |
| 22–24 | Scope, opt-in invasive testing, audit, existing auth and permission hook |
| 28, 35 | Test matrix, release gates, completion criteria and handoff checklist |

All requirements are either assigned implementation work or explicitly bounded by existing adapter/runtime support. Unsupported cloud/Kubernetes/Windows execution and future scanners remain honest coverage gaps, not implied functionality.

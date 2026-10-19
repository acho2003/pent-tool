# URL-only Kubernetes exposure scanning

## Goal

Add an opt-in black-box assessment capability for an approved HTTP(S) URL that
may be served by Kubernetes. It must identify externally reachable Kubernetes
management surfaces and report evidence of Kubernetes exposure or information
leakage, without requiring a kubeconfig, cluster access, source tree, or image.

This is an external web assessment. It does not inspect Pods, RBAC, Secrets,
NetworkPolicies, service accounts, image contents, or cluster configuration.
The existing `kube-bench` adapter remains a separate cluster-context audit.

## Current repository context

- Web/API assessments use target-bound `assessment.AppScope` rules, including
  origin, port, path-prefix, and request exclusions.
- The scanner registry and assessment planner expose scanner applicability,
  availability, and reasons to the UI.
- Native API checks, ZAP, Nuclei, Katana, and the browser discovery engine
  already feed normalized findings, artifacts, and coverage.
- Kubernetes has a typed cluster target and an opt-in `kube-bench` runner, but
  no URL-only Kubernetes-specific checks.
- A completed scanner process is not proof that every check ran; reports retain
  job status, coverage, and limitations.

## Product behavior

Add a distinct optional scanner named `kube-exposure` to Web/API assessments.
It is available for an explicit URL target and runs only when selected (or when
the operator chooses a preset that explicitly includes it). The preview shows
the exact bounded request plan and the endpoints that are outside the supplied
scope are omitted with a reason. The report separates confirmed observations,
probable fingerprints, and inconclusive responses.

Initial safe checks:

1. Inspect the supplied URL response and same-origin, in-scope redirects for
   Kubernetes-related headers, default ingress responses, and identifiable
   control-plane branding or error signatures.
2. Check a small, fixed catalog of well-known exposed management paths only
   when each candidate remains within the approved origin, port, and path
   prefix and is not excluded. Use GET/HEAD only, no credentials unless the
   operator explicitly bound them to that target, no form submission, and no
   mutation methods.
3. Recognize common exposed surfaces such as Kubernetes Dashboard, Argo CD,
   Prometheus, Grafana, and an unauthenticated Kubernetes API response. Report
   a service fingerprint as informational unless the response proves an
   actionable exposure; do not claim that a generic 200/401/403 proves a
   vulnerability.
4. Detect response evidence that discloses internal service DNS names,
   namespace/pod identifiers, or Kubernetes control-plane details. Redact
   credentials, tokens, cookies, and sensitive query values in stored evidence.
5. Bound requests by a small configured maximum, existing time/rate budgets,
   redirect policy, and the per-assessment request budget. Never follow a
   redirect outside the approved scope.

The initial catalog is versioned in code and deliberately small. No port scan,
DNS expansion, directory brute force, guessed namespace access, cloud metadata
request, credential guessing, exploit payload, or active cluster API operation
is part of this capability. Those require separate designs and explicit scope.

## Scope and safety requirements

- Derive every request from the selected URL target and the accepted
  `AppScope`; do not use a hostname-only or origin-root fallback.
- A URL scoped to `/customer/app` must not cause checks against `/api`, `/`, or
  another path outside `/customer/app`.
- Normalize paths before scope and exclusion checks; reject ambiguous paths,
  userinfo URLs, unsupported schemes, and cross-origin redirects.
- GET/HEAD are the only methods in the first release. Avoid query parameters
  except fixed harmless cache-busters if required by a fixture, and prefer none.
- Honor configured exclusions for every request, including redirects and
  browser-implicit requests.
- Use the shared request budget/rate limiter and emit a limitation when a
  request cannot be made; do not silently call the check complete.
- Do not treat generic server headers, ingress error pages, or technology
  fingerprints as confirmed vulnerabilities.
- Preserve response evidence through the existing finding sanitizer and
  artifact/report pipeline. Do not persist full response bodies by default.

## Architecture and implementation slices

### 1. Assessment and registry integration

- Add `kube-exposure` as a Web/API registry definition with URL target
  applicability, low-risk classification, optional selection, and a clear
  summary that it checks externally visible Kubernetes-related surfaces.
- Wire the scanner into the typed assessment job builder and runtime
  availability checks. It is a native Go adapter and must not depend on a
  separately installed executable.
- Keep `KUBERNETES` cluster assessment and `kube-bench` capability semantics
  unchanged. Do not label a URL scan as a cluster audit.
- Ensure plan preview distinguishes unsupported cluster access from the
  available URL-only checks.

### 2. Native scanner and check catalog

- Implement `internal/scanner/kube_exposure.go` with an injectable HTTP client,
  context cancellation, shared budget use, target-bound auth behavior, and
  structured run status/limitations.
- Implement a versioned catalog of candidate paths and signature rules in a
  separate file. Each catalog entry includes method, relative path, purpose,
  response predicates, severity ceiling, and evidence-redaction policy.
- Reuse existing scope/exclusion and redirect validation helpers. Do not make
  raw `http.Client` requests that bypass the assessment gateway or request
  recorder; if an existing helper cannot provide the required provenance and
  budget semantics, extend that shared layer first.
- Keep response reads bounded (headers and a small body prefix), enforce
  content-length/read limits, and avoid saving arbitrary page contents.
- Emit stable source IDs and normalized findings with evidence references so
  deduplication and reports work like other scanners.

### 3. Finding confidence and classifications

- Define explicit classifications: `confirmed_exposure`, `probable_service`,
  `information_disclosure`, and `inconclusive`.
- A finding can be confirmed only when a response predicate establishes
  unauthenticated access to a sensitive function or data, not merely that a
  product name or endpoint exists.
- Fingerprints alone become informational observations or coverage notes.
- Include the exact in-scope request URL (sanitized), status, selected safe
  response indicators, and why the predicate matched. Never include secret
  response values.
- Record negative/unreachable checks as coverage outcomes, not findings.

### 4. Planner, API, and UI

- Add scanner metadata and controls to New Assessment using existing optional
  scanner selection conventions; do not add a new assessment type solely for
  URL exposure checks.
- Ensure the preview displays request count, candidate paths (or a concise
  grouped view), target boundary, and omissions due to scope/exclusions.
- Persist selection/catalog version in the plan fingerprint so changes require
  plan re-review and completed checks are not incorrectly reused.
- Include run outcome and per-check coverage in Scan Detail, exported reports,
  and API coverage projections. Mark partial when request/time budget stops
  checks early.

### 5. Documentation

- Document URL-only black-box coverage and its limits in `docs/web-api-workflow.md`.
- Update `tools.md` and relevant README assessment descriptions.
- Explicitly distinguish this external exposure assessment from
  `kube-bench`/cluster credential audits.

## Test and acceptance plan

Tests use local HTTP fixtures only; do not scan public services as part of
implementation validation.

1. Unit-test catalog determinism, path joining, URL normalization, sensitive
   evidence redaction, signature matching, and severity/confidence rules.
2. Test scope and policy: exact origin/port/path-prefix, exclusions, encoded
   separators/dot segments, cross-origin redirect refusal, and no POST/PUT/
   PATCH/DELETE requests.
3. Test bounded response behavior, timeouts, cancellation, request budgets,
   oversized responses, and partial coverage reporting.
4. Test fixture responses for Kubernetes API, Dashboard, Argo CD, Grafana,
   Prometheus, generic ingress 404/502 pages, and non-Kubernetes lookalikes.
   Generic status codes and branding-only matches must not produce confirmed
   vulnerability findings.
5. Test planner applicability for explicit URL targets, no applicability for
   source/image/cluster targets, opt-in selection, unavailable/failed runs, and
   separation from the `kube-bench` job.
6. Test finding persistence, sanitization, deduplication, API projections,
   report rendering, and coverage summary consistency.
7. Run focused Go tests, full Go tests, `go vet`, frontend typecheck/build, and
   the existing local staged workflow acceptance suites before release.

Release acceptance requires all of the following:

- Preview is network-free and shows a stable, fingerprinted plan.
- Every dispatched request is within the accepted target scope and exclusions.
- No state-changing request is emitted.
- Each check has an explicit outcome; time/budget limits yield partial coverage.
- Confirmed findings include reproducible evidence and safe controls; weak
  fingerprints remain informational.
- Existing web/API and cluster `kube-bench` plans remain behaviorally intact.

## Rollout

Ship initially as optional and disabled by default. Validate against disposable
local fixtures and an operator-owned staging deployment. Review false-positive
rates before considering default selection. Keep the endpoint catalog version
in the plan fingerprint and release notes.

## Known limits

A URL cannot establish whether a web application is hosted on Kubernetes with
certainty; ingress, reverse proxy, and application behavior can obscure the
platform. This capability reports observed external exposures and evidence,
not a definitive inventory of the underlying cluster. Internal cluster
configuration remains out of reach without cluster credentials or supplied
manifests.

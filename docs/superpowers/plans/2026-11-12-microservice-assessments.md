# Microservice Assessments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scan many microservices in one assessment with a shared log-in-once bearer token, private-registry image scans, and a per-service report.

**Architecture:** `services` is a grouping layer over ordinary targets; planning is unchanged. `TOKEN_LOGIN` is a new web access kind resolved once per credential inside the existing single-context authentication pass and injected per target through the existing header map. `REGISTRY_CREDENTIALS` follows the runtime-only cloud-credential pattern into Trivy env vars. The report maps job scope (`app:<id>`/`host:<id>`) → target → service.

**Tech Stack:** Go 1.26 (net/http, httptest, gopkg.in/yaml.v3), React/TypeScript (webui), fpdf report.

**Spec:** docs/superpowers/specs/2026-11-12-microservice-assessments-design.md

## Global Constraints

- Never forward credentials to an origin not explicitly bound; discovered origins never receive the token.
- Password goes only to `login_url`, whose origin must equal an assessment URL target origin and be inside its app scope.
- Token and registry password are runtime-only: never persisted, logged, or in artifacts; added to secret redaction lists.
- No invented verification: without a protected path that proves contrast, state is `available` with an explicit reason, never `verified`.
- Records without `services` behave exactly as before.
- Commit each task separately on `main`; no Co-Authored-By trailer; do not push.
- Tests: `CGO_ENABLED=0 go test ./...`; UI `npm --prefix webui run typecheck` and build (never concurrently with Go tests).

---

### Task 1: Assessment model — services and new access kinds

**Files:** Modify `internal/assessment/types.go`, `internal/assessment/validate.go`, `internal/assessment/capabilities.go`; Test `internal/assessment/services_test.go`.

**Produces:**
- `type Service struct { ID, Name string; TargetIDs []string }`, `AssessmentConfig.Services []Service \`json:"services,omitempty"\``.
- `AccessTokenLogin AccessKind = "TOKEN_LOGIN"`, `AccessRegistryCreds AccessKind = "REGISTRY_CREDENTIALS"` (added to `AllAccessKinds`).
- `func (c AssessmentConfig) ServiceForTarget(targetID string) (Service, bool)`.

- [ ] Tests: valid two-service config passes; duplicate ID, duplicate name (case-insensitive), unknown target, target in two services, empty service, bad name (>128/newline) are blocking; TOKEN_LOGIN bound to several URL targets passes, to a non-URL target blocks; REGISTRY_CREDENTIALS bound to a non-image target blocks; Normalize trims names/IDs; capabilities: TOKEN_LOGIN yields `CapAuthWeb` available per target; REGISTRY_CREDENTIALS yields `CapImage` available.
- [ ] Implement; run `CGO_ENABLED=0 go test ./internal/assessment/`; commit `feat(assessment): services grouping and token/registry access kinds`.

### Task 2: Token login resolution

**Files:** Create `internal/web/token_login.go`, `internal/web/token_login_test.go`; modify `internal/web/assessment_auth.go`, `internal/web/assessment_auth_contexts.go`, `internal/web/credential_handlers.go` (test-credential endpoint), `internal/credentials/vault.go` only if kind-specific validation is required.

**Produces:**
- `type tokenSession struct{ mu sync.Mutex; values map[string]string; allowed []string; header string; token string; expiry time.Time; renewals int }`
- `func obtainLoginToken(ctx context.Context, values map[string]string, allowedOrigins []string) (token string, expiry time.Time, err error)` — fixed secret-free errors; `tokenConfigError` type for configuration problems.
- `func extractToken(body []byte, path string) (string, error)`; `func jwtExpiry(token string) time.Time`.
- `func (t *tokenSession) headerLine() string`, `func (t *tokenSession) renew(ctx) (string, error)` (shared lock, `maxSessionRenewals`).
- In `prepareSingleContextAuthentication`: TOKEN_LOGIN branch with a per-call `map[credentialID]*tokenSession`; verification: with `verify_url` → `probeHeaderSession` + marker/negative control or anonymous contrast → verified/failed; without → contrast on target URL; pass → verified, else `available` "token applied; access not verified (no protected path supplied or anonymous response identical)" and jobs still authenticated.
- Sessions retained on the Server keyed by plan fingerprint+identity for `assessmentAuthRefreshers`, which for TOKEN_LOGIN targets returns a refresher that re-logs-in when the JWT is near expiry or the positive check fails, replacing the `Authorization` line.

- [ ] Tests (httptest): auth server counting logins issuing JWT with exp; services A,B requiring the bearer. One login for both; both verified with protected path; service without path and identical anon response → `available`, jobs authenticated; login URL on non-target origin → unavailable, no request sent to it; token never in `json.Marshal(plan)`; unbound target gets no header; refresher on expired token performs exactly one login shared by A and B; renewal limit; form body format with extra fields; token path auto-detect and explicit `data.token`; malformed/missing token → failed.
- [ ] Implement; `CGO_ENABLED=0 go test ./internal/web/ -run 'Token|Auth'`; commit `feat(auth): log-in-once token credential shared across services`.

### Task 3: Registry credentials for Trivy

**Files:** Create `internal/web/assessment_registry_auth.go` (+test); modify `internal/scanner/types.go` (Config.AssessmentRegistryCreds, Request.RegistryCredential), `internal/scanner/assessment_jobs.go` (wire + tag allowance), `internal/scanner/pipeline.go` (buildTrivyArtifact env + secrets + digest note), `internal/web/deterministic_scan.go`; tests in `internal/scanner/trivy_registry_test.go`.

**Produces:** `type RegistryCredential struct{ Registry, Username, Password string }`; `func imageRegistryHost(ref string) string`; `func trivyScannedDigest(artifact string) string`.

- [ ] Tests: env `TRIVY_USERNAME/PASSWORD` set only when image host matches; mismatch → no env + limitation; password in `req.Secrets`; tag refs accepted in White Box with `mutable_image_tag` limitation; digest still accepted; Docker Hub short names map to `index.docker.io`; digest extracted from Trivy JSON fixture.
- [ ] Implement; scanner+web tests; commit `feat(trivy): private registry login and tag image references`.

### Task 4: Services import endpoint

**Files:** Create `internal/web/services_import.go` (+test); route in the server router.

**Produces:** `POST /api/services/parse` → `{services:[{name,urls[],image,repo,protected_path}], errors:[{row,message}]}`.

- [ ] Tests: CSV with header (any column order, BOM tolerated), multi-URL `;`, YAML list with `url` or `urls`, missing name, bad URL scheme, duplicate names, >1 MiB → 413, unknown format → 400, JSON content type set.
- [ ] Implement; commit `feat(web): CSV/YAML services import`.

### Task 5: Per-service report and scan-detail data

**Files:** Create `internal/web/report_services.go` (+test); modify `internal/web/report_scopes.go` (Service field), `internal/web/report.go` (overview table + grouping + version bump), the scan detail API to expose `services` overview.

**Produces:** `type reportService struct{ ID, Name string; Targets []string; Counts map[string]int; Auth string; Completed, Failed, Skipped int }`; `func buildReportServices(cfg assessment.AssessmentConfig, plan caps, scopes []reportScope, vulns []VulnSummary) []reportService`.

- [ ] Tests: findings mapped by scope to the right service; ungrouped → "Other targets"; auth state from capabilities (verified/available/failed); run status counts; legacy config without services → nil and report unchanged.
- [ ] Implement; `CGO_ENABLED=0 go test ./internal/web/`; commit `feat(report): per-service overview and grouping`.

### Task 6: New Scan UI and scan detail

**Files:** Create `webui/src/components/services-setup.tsx`, `webui/src/components/token-login-setup.tsx`, `webui/src/components/registry-login-setup.tsx`; modify `webui/src/pages/new-scan.tsx`, `webui/src/pages/scan-detail.tsx`, `webui/src/api/client.ts`, `webui/src/types/api.ts`; regenerate `internal/web/static`.

- [ ] Services table (add/remove, import, export CSV) generating targets `svc-<n>-url-<k>|image|repo` and `services`; token login form with service checkboxes (default all) producing one vault record and one binding per ticked target carrying the service's protected path; registry form when images exist; services overview card on scan detail.
- [ ] `npm --prefix webui run typecheck && npm --prefix webui run build`; commit `feat(webui): services table, shared token login and registry login`.

### Task 7: Docs and full verification

- [ ] Update `docs/unified-scanning-workflow.md` (services, TOKEN_LOGIN, registry) and CLAUDE.md progress section.
- [ ] `CGO_ENABLED=0 go test ./...`, `go test -race ./internal/assessment ./internal/credentials`, gofmt, `git diff --check`; commit `docs: microservice assessments`.

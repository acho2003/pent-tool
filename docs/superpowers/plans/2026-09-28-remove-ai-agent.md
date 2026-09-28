# Remove All AI / LLM / Autonomous-Agent Functionality — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strip the product down to the deterministic scanner pipeline only — remove the autonomous LLM agent, the AI report enrichment, all LLM provider/credential machinery, and the agent tool catalog, leaving a self-contained deterministic scanner + web dashboard + CLI that never talks to an LLM.

**Architecture:** The deterministic scanner (`internal/scanner`) is already self-contained (imports no internal packages) and AI scan execution is already disabled at the dispatch layer (`executeScanSession` → `executeDeterministicScanSession`; the AI wildcard body is dead code). This refactor deletes the now-dead/unreachable AI subsystems, trims the few shared packages (`internal/tools/reporting`) to drop their LLM/tool coupling, and prunes AI config/routes/UI. The compiler and the existing deterministic test suite are the safety net.

**Tech Stack:** Go 1.x (backend), React + TypeScript + Vite (webui). Tests run with `CGO_ENABLED=0` (macOS segfault gotcha).

**Spec:** This plan is self-contained (no separate spec doc); it is derived from a four-part dependency audit recorded in the branch discussion.

## Global Constraints

- **Branch:** `refactor/remove-ai-agent` (already created off `fix/zap-testssl-robustness`).
- **Keep the build green at every task boundary.** Verification for every backend task: `CGO_ENABLED=0 go build ./...`. Full gate before finishing a phase: `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...`.
- **Frontend gate:** `cd webui && npm run typecheck` (never `npm run build` in-tree — repo rule).
- **Never delete or weaken the deterministic scanner** (`internal/scanner/*`) or the deterministic report path (`generateScannerReport`, `GenerateCLIReport`, `fallbackReportFindings`).
- **Do NOT remove these dual-use / shared items:** `config.SourceRepo` (Trivy `--source` input), `config.DataDir`, `config.ScanHeaders`, all scanner tool paths/timeouts, ZAP/GVM settings, Discord/Telegram notifications, rate-limit settings, dashboard auth (`/api/auth/login|logout|status`), the `events []WSEvent` replay buffer on `ScanInstance`, `activity_policy.go`'s `normalizeActivityMode`/`normalizeScanRequestActivity`/`normalizeScheduleActivity`, `notify.go` in its entirety (Telegram API base is not an LLM endpoint), and `codescan.go`'s `isBlockedTargetForScan`.
- **Attribution:** per repo rule, do NOT add a `Co-Authored-By: Claude` trailer to commits.
- Commit after each task (frequent commits).

---

## Phase 0 — Baseline

### Task 0: Confirm green baseline
**Files:** none (verification only).

- [ ] **Step 1:** Run `CGO_ENABLED=0 go build ./...` — Expected: success.
- [ ] **Step 2:** Run `CGO_ENABLED=0 go test ./internal/scanner/ ./internal/web/ 2>&1 | tail` — Expected: pass (records the pre-refactor state).
- [ ] **Step 3:** Run `cd webui && npm run typecheck` — Expected: clean.

---

## Phase 1 — Backend: delete whole-AI HTTP surface (web routes + AI-only handlers)

Doing routes + their handler files together keeps the package compiling.

### Task 1: Remove AI HTTP routes and their handlers
**Files:**
- Modify: `internal/web/server.go` (route registrations in `Start`, ~lines 1029–1132; `dashboardRoutes` slice ~574–624)
- Modify: `internal/web/handlers_helpers.go` (remove `handleListProviders`, `writeCatalogError`; keep `limitJSONBody`, `writeJSONStatus`, `jsonWriteBodyLimit`)
- Modify: `internal/web/handlers_router.go` (remove `handleProviderKeys` + GET/POST/DELETE sub-handlers, `handleTestRoute`; keep any deterministic helpers/`KnownProviderIDs` usage — if `handlers_router.go` becomes empty, delete it)
- Modify: `internal/web/settings_env.go` (remove `handleLLMSettings`; **keep** `handleEnvironmentSettings`)
- Delete: `internal/web/handlers_profiles.go`
- Delete: `internal/web/handlers_provider_models.go`

**Routes to remove** (string → handler): `/api/settings/llm` → `handleLLMSettings`; `/api/settings/llm/keys` → `handleProviderKeys`; `/api/settings/llm/test-route` → `handleTestRoute`; `/api/providers` → `handleListProviders`; `/api/providers/` → `handleDiscoverProviderModels`; `/api/auth/profiles` → `handleListProfiles`; `/api/auth/profiles/api-key` → `handleCreateAPIKeyProfile`; `/api/auth/profiles/oauth/start` → `handleOAuthStart`; `/api/auth/profiles/oauth/complete` → `handleOAuthComplete`; `/api/auth/profiles/` → `handleProfileRefresh`/`handleDeleteProfile`. Also remove these strings from the `dashboardRoutes` test-surface slice.

**Routes to KEEP:** `/`, `/ws`, `/api/scan`, `/api/stop`, `/api/restart`, `/api/status`, `/api/legacy-import/status`, `/api/scans`, `/api/scans/`, `/api/data-dirs/`, `/api/schedules`, `/api/schedules/`, `/api/upload-targets`, `/api/upload-logo`, `/api/upload-context`, `/api/findings`, `/api/findings/summary`, `/uploads/logos/`, `/api/report/`, `/api/reports/`, `/api/scanners/status`, `/api/settings/rate-limit`, `/api/settings/environment`, `/api/queue/*`, `/api/version`, `/api/instances`, `/api/instances/`, `/api/auth/login|logout|status`.

- [ ] **Step 1:** Delete `handlers_profiles.go` and `handlers_provider_models.go`.
- [ ] **Step 2:** Remove the AI route registrations from `server.go` `Start` and the matching entries from `dashboardRoutes`.
- [ ] **Step 3:** Remove `handleLLMSettings` from `settings_env.go`; remove `handleListProviders`/`writeCatalogError` from `handlers_helpers.go`; remove `handleProviderKeys`/`handleTestRoute` from `handlers_router.go`.
- [ ] **Step 4:** Delete the now-orphaned AI handler tests: `handlers_profiles_test.go`, `handlers_provider_models_test.go`, `handlers_profiles_error_test.go`, `handlers_provider_models_test.go`, `oauth_paste_test.go`, and any `settings_env`/router test asserting removed routes. (Build will tell you which remain.)
- [ ] **Step 5:** Run `CGO_ENABLED=0 go build ./internal/web/` — expect failures only from still-referenced AI symbols (fixed in later tasks) OR success. Note remaining refs.
- [ ] **Step 6:** Commit: `refactor(web): remove AI provider/profile/LLM HTTP routes and handlers`.

---

## Phase 2 — Backend: delete whole-AI web files & post-scan chat

### Task 2: Delete autonomous + chat + LLM-resolver web files
**Files:**
- Delete: `internal/web/autonomous.go` (LLM prompt builders)
- Delete: `internal/web/chat.go` (post-scan LLM chat; `handleChat` is not even mux-registered)
- Delete: `internal/web/scan_resolve.go` (LLM credential resolution; `modelForConfiguredProvider` dies with `handleLLMSettings` from Task 1)
- Delete tests: `chat` coverage in `server_test.go` (surgical — see Task 9), `scan_resolve` tests if any, `abort_instance_gate_test.go` (exercises `shouldFailInstanceOnAbort`, removed in Task 5).

**Interfaces removed for later tasks:** `buildAutonomousInstruction`, `buildDASTInstruction`, `buildPhaseFilterInstruction`, `buildSubdomainScanInstruction` (autonomous.go); `postScanChatFn`, `chatCfg`, `chatMessages` consumers (chat.go); `resolveScanCredentials`, `buildScanLLMClient`, `scanLLMClientForRequest` (scan_resolve.go).

- [ ] **Step 1:** Delete the three files above.
- [ ] **Step 2:** Run `CGO_ENABLED=0 go build ./internal/web/` — note references to deleted symbols in `orchestrator.go`, `scan_session.go`, `server.go` (expected; fixed next tasks).
- [ ] **Step 3:** Commit: `refactor(web): delete autonomous, post-scan chat, and LLM resolver files`.

---

## Phase 3 — Backend: surgical edits to mixed web files

### Task 3: Trim `report_ai.go` to deterministic-only (keep the report generator!)
**Files:** Modify `internal/web/report_ai.go` (consider renaming to `report_generate.go` at the end).

- [ ] **Step 1:** Remove `aiReportFindings`, `aiFindingKey`, `matchAIFinding`.
- [ ] **Step 2:** In `generateScannerReport`, remove the AI branch (the `if enriched, err := s.aiReportFindings(...)` block that sets `manifest.Mode="ai"`/`Model`/`Provider`, plus its `else if err` log). The manifest already defaults to `Mode: "deterministic_fallback"` via `fallbackReportFindings`.
- [ ] **Step 3:** Remove the `internal/llm` import.
- [ ] **Step 4:** Keep `GenerateCLIReport`, `generateScannerReport`, `fallbackReportFindings`, `reportFindingsToVulns`, `reportScanners`, `reportEvidenceRefs`, and the `reportManifest`/`reportFinding` structs.
- [ ] **Step 5:** Update `report_ai_test.go` — delete AI-enrichment test cases, keep deterministic ones (or move to a `report_generate_test.go`).
- [ ] **Step 6:** `CGO_ENABLED=0 go build ./internal/web/` — this file should now compile. Commit: `refactor(web): drop AI report enrichment, keep deterministic report generator`.

### Task 4: Trim `codescan.go` and `activity_policy.go`
**Files:** Modify `internal/web/codescan.go`, `internal/web/activity_policy.go`.

- [ ] **Step 1:** In `codescan.go` remove `resolveCodeScan`, `pickLoopbackPort`, `codeTargetLabel`, and the `agent` import (and now-unused `net`/`filepath`). **Keep `isBlockedTargetForScan`** and its `scopeguard` import.
- [ ] **Step 2:** In `activity_policy.go` remove `buildActivityPolicyInstruction`. **Keep** `normalizeActivityMode`, `normalizeScanRequestActivity`, `normalizeScheduleActivity`, and the `activityMode*` consts.
- [ ] **Step 3:** `CGO_ENABLED=0 go build ./internal/web/` (expect remaining refs from orchestrator/scan_session/server). Commit: `refactor(web): trim code-scan and activity-policy to deterministic helpers`.

### Task 5: Trim `scan_session.go` (remove agent event/instruction code)
**Files:** Modify `internal/web/scan_session.go`.

- [ ] **Step 1:** Remove `processEvent` (the `agent.Event` handler; no callers), and the now-dead `inferCurrentPhase`, `parsePhaseMention`, `mapValues`, and the `phaseMentionRe` var.
- [ ] **Step 2:** Remove `buildSeverityPrefix`, `shouldFailInstanceOnAbort`, `isReconReportOnlyPhaseSelection`.
- [ ] **Step 3:** Remove the `agent` and `reporting` imports (only `processEvent` used them). Keep `executeScanSession` (deterministic dispatcher → `executeDeterministicScanSession`), `firstSelectedPhase`, `phaseAllowed`, `minInt`.
- [ ] **Step 4:** `CGO_ENABLED=0 go build ./internal/web/`. Commit: `refactor(web): remove agent event processing from scan_session`.

### Task 6: Collapse the dead AI wildcard body and AI fields in `orchestrator.go`
**Files:** Modify `internal/web/orchestrator.go`.

- [ ] **Step 1:** In `runWildcardTarget`, delete everything after the deterministic early-return (the AI body, roughly lines 722–1181), leaving the function as just the `runDeterministicWildcard` delegation. Remove the `agent` import (only `agent.EffectiveRequestRatePolicy` in that block used it).
- [ ] **Step 2:** Delete the now-dead helpers used only by that block: `commandRateForPolicy`, `commandDelayForPolicy`, `buildDiscoveryInstruction`, `buildPassiveDiscoveryInstruction`, `collectSubdomains`, `cleanTmpSubdomainFiles` (verify each has no remaining caller with grep before deleting).
- [ ] **Step 2b:** `runDASTTarget` is unreachable (handleScan maps `dast`→`single`). Remove `runDASTTarget` and its `case "dast"` dispatch (~line 429). (If a reviewer prefers keeping DAST, instead strip its AI instruction building and sess fields — but removal is cleaner since it's dead.)
- [ ] **Step 3:** In `runSingleTarget`, remove AI instruction building and AI-only `scanSession` fields at construction (`instruction: buildAutonomousInstruction(...)`, `codeScanMode`, `allowLoopbackPorts`, `discoveryMode`, `llmClient`, `userInstruction`, `sourceRepo`, `scanContext`, `targetAuthB`). Keep deterministic fields.
- [ ] **Step 4:** Remove `s.currentAgents` operations (`delete(s.currentAgents, ...)`, `instance.agent = nil`) that reference removed fields — coordinate with Task 7's struct-field removal (do the field removal first if the build complains, or stub together).
- [ ] **Step 5:** `CGO_ENABLED=0 go build ./internal/web/`. Commit: `refactor(web): drop dead AI wildcard/DAST orchestration`.

### Task 7: Remove AI fields & wiring from `server.go` structs and `NewServer`
**Files:** Modify `internal/web/server.go`.

- [ ] **Step 1:** Remove Server fields: `currentAgents`, `postScanChatFn`, `catalog *providers.Service`, `profiles *auth.Store`, `oauthRegistry *auth.Registry`, `llmKeyStore *llm.KeyStore`, `llmRouter *llm.Router`; and their `NewServer` construction/wiring.
- [ ] **Step 2:** Remove agent/llm fields from `ScanInstance` (`agent`, `chatCfg`, `chatMessages`, `lastSessionTokens`), and from `scanSession` (`agent`, `events chan agent.Event`, `recordTokenOffset`, `instruction`, `discoveryMode`, `phases`?, `reconMode`?, `scanIntensity`?, `targetAuthB`, `sourceRepo`, `scanContext`, `codeScanMode`, `allowLoopbackPorts`, `llmClient`, `skipNotesCleanup`, `parentReportingCtxID`, `abortReason`). **Keep** `events []WSEvent` on `ScanInstance` (WS replay buffer) and `sctx` handling only as needed by `cleanup()` (see Step 4).
- [ ] **Step 3:** Remove all `inst.agent.Stop()` / `agnt.Stop()` / `sess.agent.Stop()` call sites (server.go stop/shutdown loops) and the `var agents []*agent.Agent` block.
- [ ] **Step 4:** Simplify `scanSession.cleanup()`: drop `sess.agent.Stop()`, `agentsgraph.Reset()`, `notes`/`terminal`/`browser` teardown, `delete(currentAgents,...)`. Keep only the deterministic reporting/scanctx teardown that the deterministic path actually creates (deterministic sessions never set `sctx`/`agent`, so most becomes no-op — remove rather than nil-guard).
- [ ] **Step 5:** Drop imports: `agent`, `auth`, `providers`, `internal/tools/agentsgraph`, `internal/tools/browser`, `internal/tools/notes`, `internal/tools/terminal`, and `llm` (verify none remain).
- [ ] **Step 6:** Decide ScanRequest AI-field removal (`Instruction`, `Model`, `APIKey`, `APIBase`, `TargetAuthSecondary`, `SourceRepo`?(KEEP — dual-use Trivy), `CodeScan`, `ScanContext`, `ProviderProfile`, `codeScanMode`, `allowLoopbackPorts`). **Keep `SourceRepo`.** Remove the others. For `Instruction`/`ReconMode`/`ScanIntensity`/`Phases` see Task 8.
- [ ] **Step 7:** `CGO_ENABLED=0 go build ./internal/web/`. Commit: `refactor(web): remove agent/LLM fields and wiring from server`.

### Task 8: (Optional) strip inert `Instruction`/`ReconMode`/`ScanIntensity` persistence
**Files:** Modify `internal/web/scan_record.go`, `queue_state.go`, `scan_query.go`, and the struct defs in `server.go` (`ScanRecord`, `ScanInstance`, `QueueState`).

> These fields are persisted/echoed but never drive the deterministic scan. Removing them is a clean-up; if it risks churn, leave them inert. `ReconMode`/`ScanIntensity` still flow through `normalizeActivityMode` (kept) — if you keep the fields, keep those assignment sites.

- [ ] **Step 1:** If removing: delete the fields from the four structs and every assignment site (`scan_record.go:45,77-78,243-244`, `queue_state.go:21,217,274-275,323`, `scan_query.go:341,750`).
- [ ] **Step 2:** `CGO_ENABLED=0 go build ./...`. Commit: `refactor(web): drop inert agent instruction/activity fields` (skip if not doing).

---

## Phase 4 — Backend: delete AI packages and trim shared `reporting`

### Task 9: Fix web tests, then delete `internal/agent`, `internal/llm`, `internal/auth`, `internal/providers`
**Files:**
- Modify: `internal/web/server_test.go` and any remaining web tests referencing removed symbols (chat, agents, profiles).
- Modify: `internal/tui/tui.go` only if it referenced removed symbols (it should not — it uses `GenerateCLIReport` + scanner + config).
- Delete dirs: `internal/agent/`, `internal/llm/`, `internal/auth/`, `internal/providers/`.

- [ ] **Step 1:** `CGO_ENABLED=0 go vet ./internal/web/ 2>&1 | head -50` — enumerate test compile failures; delete/trim those test cases (whole-file delete for AI-only test files).
- [ ] **Step 2:** Confirm nothing outside the doomed packages imports them: `grep -rl 'internal/\(agent\|llm\|auth\|providers\)' --include='*.go' internal cmd | grep -v -E 'internal/(agent|llm|auth|providers)/'` → should list only files already trimmed (expect empty after Tasks 1–8).
- [ ] **Step 3:** `git rm -r internal/agent internal/llm internal/auth internal/providers`.
- [ ] **Step 4:** `CGO_ENABLED=0 go build ./...`. Commit: `refactor: delete agent, llm, auth, and providers packages`.

### Task 10: Trim `internal/tools/reporting`, then delete agent tool packages
**Files:**
- Modify: `internal/tools/reporting/reporting.go` (remove `Register`, `reportVulnForRegistry`, the `tools.Result`-returning report path; keep the vulnerability store: `Vulnerability` type, `GetVulnerabilitiesForContext`, `CleanupContext`, `ResetVulnerabilitiesForContext`, `MergeVulnsToContext`, `PromoteToParent`, `SetParentContext`, and the `scanctx` usage the store needs).
- Delete dirs: `internal/tools/{agentmail,agentsgraph,browser,codesearch,fileedit,finish,httpclient,iolimit,notes,oob,pageagent,proxy,python,skills,terminal,websearch}` and `internal/oob`.
- Delete files: `internal/tools/exec.go`, `internal/tools/registry.go` (top-level tool registry — only reporting linked it, now trimmed).

- [ ] **Step 1:** Trim `reporting.go` to remove the `internal/tools` dependency (drop `Register` + `tools.Result` helpers + the `internal/tools` import). Keep the store API that `scan_record.go`/`scan_query.go` call.
- [ ] **Step 2:** `CGO_ENABLED=0 go build ./internal/tools/reporting/ ./internal/web/` — reporting must compile without `internal/tools`.
- [ ] **Step 3:** `git rm` the agent tool subpackages listed above + `internal/oob` + `internal/tools/exec.go` + `internal/tools/registry.go` (and their `_test.go`).
- [ ] **Step 4:** Resolve fallout in `internal/scanctx`, `internal/sandbox`, `internal/resources` (compiler-guided): delete files that only served deleted tools (e.g. `scanctx/browserstate.go` if now unused; whatever in `sandbox`/`resources` is orphaned), but **keep** what `reporting` and `cmd/xalgorix/main.go` still import. Principle: delete-until-it-compiles, never touching scanner/config/tui deterministic needs.
- [ ] **Step 5:** `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go vet ./...`. Commit: `refactor: trim reporting store and delete agent tool packages`.

---

## Phase 5 — Backend: config & CLI

### Task 11: Remove AI config fields and env vars
**Files:** Modify `internal/config/config.go`, `internal/config/config_test.go`; check `internal/resources/llm.go`.

**Remove (AI-only):** `LLM`, `LLMProvider`, `APIBase`, `APIKey`, `LLMProfile`, `ReasoningEffort`, `OllamaCompatible`, `Temperature`, `LLMMaxRetries`, `MemCompTimeout`, `MaxOutputTokens`, `ContextCompactTokens`, `LLMContextWindow`, `ContextCompactRatio`, `MaxIterations`, `MinIterations`, `NoToolAbortAt`, `MaxFinishRejections`, `TargetAuthSecondary`, `ScanContext`, `MaxToolCalls`, `MaxTokens`, `GeminiAPIKey`, `AgentMailAPIKey`, `AgentMailPod`, `DisableBrowser`, `BrowserPath`, `AllowAutoInstall`, `AllowAutoInstallSudo`, `ReadDenyList` (+ `defaultReadDenyList`/`resolveReadDenyList`), `SkillsDir`, and the OOB fields (`OOBPublicURL`, `OOBPort`, `InteractshServer`, `InteractshToken`, `OOBDisable`). Update `ResolveModel`, `CheckEnvFile`, and the `XALGORIX_DEBUG_CONFIG` dump to drop LLM references.

**KEEP:** `SourceRepo`, `DataDir` (+ `Workspace`/`WorkspaceRoot` aliases — rename optional but keep the value), scanner tool paths + all `*TimeoutSec`, `ScannerMaxOutputBytes`, `MaxWorkers`, ZAP/GVM, `ScanHeaders` (+ `loadScanHeaders`), `RuntimeBackend`, `ScanRetentionDays`, rate-limit fields, `TLSSkipVerify`, Caido, telemetry, Discord/Telegram, dashboard auth, `BindAddr`, `AllowLocalTargets`, proxy fields, `HomeDir`, `MaxDurationSec` (generic wall-clock cap).

- [ ] **Step 1:** Remove the AI fields + their `Load` lines.
- [ ] **Step 2:** Update `config_test.go` to drop assertions on removed env vars (XALGORIX_LLM/API_*/REASONING/OLLAMA/LLM_MAX_RETRIES/MEMORY_COMPRESSOR/MAX_ITERATIONS/DISABLE_BROWSER/BROWSER_PATH, GEMINI_API_KEY, AGENTMAIL_*).
- [ ] **Step 3:** If `internal/resources/llm.go` (XALGORIX_LLM_MAX_INFLIGHT) is now unimported (its importers were llm + agent tools, all deleted), `git rm internal/resources/llm.go` and its test; keep the rest of `internal/resources` that `main.go` uses.
- [ ] **Step 4:** `CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./internal/config/`. Commit: `refactor(config): remove AI/LLM/agent configuration`.

### Task 12: Clean CLI usage text
**Files:** Modify `cmd/xalgorix/main.go`.

- [ ] **Step 1:** In `printUsage` "Environment:" block, remove the `XALGORIX_LLM`, `XALGORIX_API_KEY`, `XALGORIX_API_BASE`, `XALGORIX_MAX_ITERATIONS` lines. Keep `XALGORIX_SCAN_HEADERS`/`_FILE`. Keep all flags (all deterministic; `--source`/`--artifact-kind` stay for Trivy).
- [ ] **Step 2:** `CGO_ENABLED=0 go build ./cmd/... && CGO_ENABLED=0 go test ./cmd/...`. Commit: `docs(cli): drop LLM env vars from usage`.

---

## Phase 6 — Frontend (webui)

### Task 13: Remove the Settings "Report AI" (LLM) tab + OAuth modal
**Files:**
- Delete: `webui/src/pages/settings/oauth-modal.tsx`
- Modify: `webui/src/pages/settings.tsx` (remove the entire `llm` tab: `TabsTrigger value="llm"`, the `<TabsContent value="llm">` block, `OAuthModal` render; remove `"llm"` from `settingsTabs` and repoint default tab to `"engagement"`; remove LLM form state/hooks/memos/functions and the LLM-only helper functions `CatalogModelField`, `bareModelForProvider`, `hasOllamaPort`, `normalizeReasoningEffort`, `isMaskedSettingValue`, `prettyAuthMethod`, `maskedAPIKeyLabel`, `maskedTokenLabel`; drop now-unused imports). Keep `engagement`, `notifications`, `environment`, `account` tabs and their hooks. Reword the "issued by the agent" rate-limit description.

- [ ] **Step 1:** Delete `oauth-modal.tsx`; make the `settings.tsx` edits above.
- [ ] **Step 2:** `cd webui && npm run typecheck` — fix unused-import errors it flags.
- [ ] **Step 3:** Commit: `refactor(webui): remove Report AI settings tab and OAuth modal`.

### Task 14: Remove AI bits from scan-detail and integrations
**Files:** Modify `webui/src/pages/scan-detail.tsx`, `webui/src/pages/integrations.tsx`.

- [ ] **Step 1:** In `scan-detail.tsx`: remove the "Regenerate report" button + `regenerating` state + `regenerate()`; remove the "Report state" card (`report_mode`/`report_generated_at`); in `ConfigTab` remove the "Recon access"/"Testing access"/Instruction rows (and optionally the agent-era Iterations/Tool calls/Tokens metrics + SubdomainsTab "Tokens" column); drop `Sparkles`/`Loader2` imports and reword the "AI is not used" copy.
- [ ] **Step 2:** In `integrations.tsx`: remove the trailing "Report AI" Card and the "Report AI is optional" header clause.
- [ ] **Step 3:** `cd webui && npm run typecheck`. Commit: `refactor(webui): drop AI report UI from scan detail and integrations`.

### Task 15: Remove AI from API client, queries, types, and mock backend
**Files:** Modify `webui/src/api/client.ts`, `webui/src/api/queries.ts`, `webui/src/types/api.ts`, `webui/mock-backend.mjs`; reword copy in `new-scan.tsx`, `overview.tsx`, `schedules.tsx`, `login.tsx`.

- [ ] **Step 1:** `queries.ts`: delete hooks `useLLMSettings`, `useUpdateLLMSettings`, `useAuthProfiles`, `useProviders`, `useDiscoverProviderModels`, `useOAuthStart`, `useOAuthComplete`, `useRefreshAuthProfile`, `useDeleteAuthProfile`; remove `qk.llmSettings/authProfiles/providers`; drop the `qk.llmSettings` invalidation in `useUpdateEnvironmentSettings`.
- [ ] **Step 2:** `client.ts`: delete `llmSettings`, `updateLLMSettings`, `listProviders`, `discoverProviderModels`, `listAuthProfiles`, `oauthStart`, `oauthComplete`, `refreshAuthProfile`, `deleteAuthProfile`, and `regenerateReport`. Keep `reportUrl`, `scannerOutput`, `scannerArtifactUrl`, `scanScopes`, `scannerStatus`.
- [ ] **Step 3:** `types/api.ts`: delete `CatalogEntry`, `AuthProfileType`, `AuthProfile`, `OAuthStartMode`, `OAuthStartSubmode`, `OAuthStartResponse`, `LLMSettings`, `LLMProfileSummary`, `LLMSettingsRequest`; remove `VersionInfo.ai`; remove AI fields on `ScanInstance`/`ScanRecord`/`QueueStatus` (`instruction`, `recon_mode`, `scan_intensity`, `report_mode`, `report_generated_at`). **Keep `ScanRequest.target_auth`, `severity_filter`, `scanners`.**
- [ ] **Step 4:** `mock-backend.mjs`: remove `/api/chat`, `/api/providers`, `/api/auth/profiles`, `/api/settings/llm` handlers + the `providerCatalog`/`llmSettings`/`authProfiles` seeds.
- [ ] **Step 5:** Reword the "report AI" descriptive copy in `new-scan.tsx`, `overview.tsx`, `schedules.tsx`, `login.tsx`.
- [ ] **Step 6:** `cd webui && npm run typecheck`. Commit: `refactor(webui): remove AI endpoints, types, and mock data`.

---

## Phase 7 — Docs & infra

### Task 16: Update docs and delete Ollama compose
**Files:** Delete `docker-compose.ollama.yml`. Update `README.md`, `tools.md`, `docs/ARCHITECTURE.md`, `docs/dockerhub-overview.md`, `docs/TESTING_CHECKLIST.md`, `Dockerfile` (comments/env examples only — keep the node webui build stage), `install.sh`, `.github/ISSUE_TEMPLATE/bug_report.yml`, `redeploy.sh` (drop `GEMINI_`/`AGENTMAIL_` from the env-capture regex).

- [ ] **Step 1:** `git rm docker-compose.ollama.yml`.
- [ ] **Step 2:** Rewrite the AI-referencing sections listed above to describe a purely deterministic scanner. In `tools.md`, remove the "🤖 Agent Tools (Built-in)" section and the "70+ tools / autonomous agent" framing; keep the deterministic scanner tool catalog.
- [ ] **Step 3:** Commit: `docs: describe deterministic-only scanner; remove AI/agent docs`.

---

## Phase 8 — Final verification

### Task 17: Full green gate
**Files:** none (verification).

- [ ] **Step 1:** `CGO_ENABLED=0 go build ./...` — success.
- [ ] **Step 2:** `CGO_ENABLED=0 go vet ./...` — clean.
- [ ] **Step 3:** `gofmt -l $(git diff --name-only --diff-filter=ACM '*.go')` — empty.
- [ ] **Step 4:** `CGO_ENABLED=0 go test ./...` — pass (the known macOS-only failures from memory excepted).
- [ ] **Step 5:** `cd webui && npm run typecheck` — clean.
- [ ] **Step 6:** `grep -rn 'internal/\(agent\|llm\|auth\|providers\)' --include='*.go' .` — no matches. `grep -rin 'autonomous\|LLM\|OpenAI\|Gemini\|Ollama' --include='*.go' internal cmd | grep -v scanner` — only benign/comment hits.
- [ ] **Step 7:** Sanity-run the deterministic scan: `CGO_ENABLED=0 go run ./cmd/xalgorix --help` shows no AI env vars; optionally a dry scan.
- [ ] **Step 8:** Final commit if any fixups: `refactor: deterministic-only scanner — remove all AI/agent functionality`.

---

## Notes / risks

- **`internal/scanctx` / `internal/sandbox` / `internal/resources` are entangled** with the kept `reporting` package and `main.go`. Do not pre-delete them; let Task 10 Step 4 prune orphaned files compiler-guided.
- **`SourceRepo` must survive** — it is the Trivy `--source` input, not just an agent whitebox feature.
- **`report_ai.go` is misnamed** — it holds the deterministic report generator. Trim, don't delete.
- **Tests are the main compile blockers.** Many `_test.go` files exercise the AI surface; delete AI-only test files and trim mixed ones (`server_test.go`, `config_test.go`, `report_ai_test.go`).
- **DAST** is already unreachable (`handleScan` maps `dast`→`single`); Task 6 removes it. Flag for reviewer if they want it kept as a deterministic alias.
- This plan supersedes the `feat/scan-engine-toggle` work (the engine toggle is moot once AI is gone); that branch can be abandoned.

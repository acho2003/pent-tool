# Scanner Report Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four gaps left after Increment 6. The AI report path must keep findings on the right host when two hosts share a source ID. OSV findings need real severities. Source-code CVE merges must respect the lockfile they came from. The PDF/manifest need small polish: source origin instead of the local checkout path, labels that fit, and manifest schema v2.

**Architecture:** All changes sit on the existing scanner → report path.
- **AI path:** `aiReportFindings` (internal/web/report_ai.go) validates AI output against a `(scope, source_id)` map. It falls back to a source-id-only match when that is unambiguous.
- **OSV parsing:** `parseOSV` (internal/scanner/parse.go) reads osv-scanner's `groups[].max_severity` / `database_specific.severity`. When neither is present it marks the finding `SeverityUnrated`, so the merge and the AI severity floor ignore its placeholder.
- **Source-scope paths:** `ParseRuns` rewrites source-scope finding paths relative to the checkout root. `mergeCrossScanner` adds the file to the merge key on source scopes.
- **Source origin:** the pipeline persists the resolved source scope next to `recon-scopes.json`. The report labels the source block by its origin (redacted clone URL, or the operator-provided directory). PDF scope labels are truncated to fit.

**Tech Stack:** Go 1.26; `internal/scanner` (parsers, merge, source persistence); `internal/web` (report manifest, AI validation, PDF via `github.com/go-pdf/fpdf`); `README.md`.

**Spec:** docs/superpowers/specs/2026-09-24-scanning-dag-pipeline-design.md (§6 source IDs, §7 contract, §8 report changes). This plan carries out the follow-ups deferred in Increment 6 (docs/superpowers/plans/2026-09-25-scanning-dag-increment-6-report-docs.md).

## Global Constraints

- **Go 1.26.** Darwin dev host: run go with `CGO_ENABLED=0` (CGO segfaults). NEVER use `go test -race`.
- **No Claude attribution:** commit messages must NOT contain a `Co-Authored-By: Claude` trailer or any other Claude attribution line. Subject + optional body only.
- **Live report path is `internal/web`:** `report_ai.go` → `generateReportAt` → `generateReport` (report.go). `internal/reporting` is an unused duplicate; do NOT modify it.
- **SourceIDs are trace keys:** never change a parser's `SourceID` format (spec §6). `EvidenceRef` stays `run.ArtifactPath + "#" + SourceID`, computed from the unmodified SourceID.
- **AI safety rule:** Report AI may only return findings grounded in its input chunk. Any output that cannot be matched to exactly one input finding rejects the whole AI response, and the report falls back deterministically. Do NOT add a static source-ID whitelist.
- **Merge rule:** merge only the same single well-formed CVE on the same scope from different scanners. On source scopes the file must also match. Merging never lowers a *rated* severity.
- **Determinism:** report ordering stays a pure function of runs + persisted scope files + parsed findings.
- **Backward compatibility:** scans without the new `source-scope.json` still render, falling back to the old label. New JSON fields are `omitempty`.
- **Mandatory gate every task:** `gofmt -l` on touched packages prints nothing (internal/agent/hooks*.go has pre-existing drift; out of scope), plus `CGO_ENABLED=0 go vet` and `CGO_ENABLED=0 go test` on touched packages.

---

## File Structure

- `internal/web/report_ai.go`: scope-keyed AI validation (`aiFindingKey`, `matchAIFinding`), prompt v2, manifest schema v2, severity floor honoring `SeverityUnrated`.
- `internal/web/report_ai_test.go`: AI tests for same-SourceID/different-scope, ambiguous fallback, unrated floor, and manifest version.
- `internal/scanner/parse.go`: `Finding.SeverityUnrated`; `parseOSV` severity + Target/Evidence; `ParseRuns` source-path relativization (`relativeToRoot`).
- `internal/scanner/merge.go`: unrated-aware severity raise; file-aware merge key on source scopes (`mergeLocation`).
- `internal/scanner/source.go`: `saveSourceScope`, `LoadSourceScope`, `sourceScopePath`. `internal/scanner/pipeline.go`: persists the source scope.
- `internal/scanner/parse_test.go`, `merge_test.go`, `source_test.go`, `pipeline_test.go`: scanner tests.
- `internal/web/report_scopes.go`: `reportScope.Origin`, `sourceOrigin`, `redactURL`.
- `internal/web/report_coverage.go`: origin-aware label, `fitPDFText`. `internal/web/report.go`: truncates the summary group label.
- `internal/web/report_scopes_test.go`, `report_coverage_test.go`: web tests.
- `README.md`: persistence note for `source-scope.json` and manifest v2.

---

### Task 1: Scope-keyed AI validation

**Files:**
- Modify: `internal/web/report_ai.go`: `reportPromptVersion` (line 19); the prompt string and `allowed` map inside `aiReportFindings` (~lines 168-195).
- Test: `internal/web/report_ai_test.go`

**Interfaces:**
- Produces: `func aiFindingKey(scope, sourceID string) string` and `func matchAIFinding(allowed map[string]scanner.Finding, bySource map[string][]scanner.Finding, scope, sourceID string) (scanner.Finding, bool)`. `reportPromptVersion` becomes `"scanner-report-v2"`. Task 2 edits the same loop (severity floor) and consumes the `src` returned by `matchAIFinding`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/web/report_ai_test.go`. The helper below builds a fake OpenAI-compatible provider the same way `TestScannerReportAIKeepsMergedTraceAndSeverityFloor` does. Reuse that test's setup lines (`s.cfg.LLM`, `APIBase`, `APIKey`, `LLMMaxRetries`) exactly.

```go
// aiProvider answers every chat request with the given findings envelope.
func aiProvider(t *testing.T, findings []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, _ := json.Marshal(map[string]any{"findings": findings})
		resp, _ := json.Marshal(map[string]any{"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": string(content)}}}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func aiServer(t *testing.T, provider *httptest.Server) *Server {
	t.Helper()
	s := newTestServer(t, nil)
	s.cfg.LLM = "report-model"
	s.cfg.APIBase = provider.URL
	s.cfg.APIKey = "test-key"
	s.cfg.LLMMaxRetries = 1
	return s
}

// Two host scopes on one IP both report the same nmap SourceID; the AI must
// keep each finding on its own host.
func TestAIReportKeepsSameSourceIDOnItsOwnScope(t *testing.T) {
	aiOut := func(scope string) map[string]any {
		return map[string]any{"source_id": "nmap:10.0.0.5:443", "scope": scope, "scanner": "nmap", "title": "Open port 443", "severity": "info", "explanation": "Port 443 is open.", "evidence_reference": "x", "impact": "Exposed service.", "remediation": "Restrict if unneeded."}
	}
	s := aiServer(t, aiProvider(t, []map[string]any{aiOut("host:a.test"), aiOut("host:b.test")}))
	in := []scanner.Finding{
		{SourceID: "nmap:10.0.0.5:443", Scanner: "nmap", Title: "https", Severity: "info", Scope: "host:a.test", Target: "a.test", EvidenceRef: "a.xml#nmap:10.0.0.5:443"},
		{SourceID: "nmap:10.0.0.5:443", Scanner: "nmap", Title: "https", Severity: "info", Scope: "host:b.test", Target: "b.test", EvidenceRef: "b.xml#nmap:10.0.0.5:443"},
	}
	out, err := s.aiReportFindings(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Scope == out[1].Scope {
		t.Fatalf("each finding must keep its own scope, got %#v", out)
	}
	for _, f := range out {
		want := map[string]string{"host:a.test": "a.xml#nmap:10.0.0.5:443", "host:b.test": "b.xml#nmap:10.0.0.5:443"}[f.Scope]
		if f.EvidenceRef != want {
			t.Fatalf("scope %s got evidence %q, want %q", f.Scope, f.EvidenceRef, want)
		}
	}
}

// An AI item that omits scope is accepted when its source_id is unique in the
// chunk, and rejected (forcing the deterministic fallback) when it is ambiguous.
func TestAIReportScopelessMatch(t *testing.T) {
	item := map[string]any{"source_id": "nmap:10.0.0.5:443", "scanner": "nmap", "title": "Open port 443", "severity": "info", "explanation": "Port 443 is open.", "evidence_reference": "x", "impact": "Exposed service.", "remediation": "Restrict if unneeded."}
	unique := []scanner.Finding{{SourceID: "nmap:10.0.0.5:443", Scanner: "nmap", Severity: "info", Scope: "host:a.test", EvidenceRef: "a.xml#nmap:10.0.0.5:443"}}
	s := aiServer(t, aiProvider(t, []map[string]any{item}))
	out, err := s.aiReportFindings(unique)
	if err != nil || len(out) != 1 || out[0].Scope != "host:a.test" {
		t.Fatalf("unique scopeless match: out=%#v err=%v", out, err)
	}
	ambiguous := append(unique, scanner.Finding{SourceID: "nmap:10.0.0.5:443", Scanner: "nmap", Severity: "info", Scope: "host:b.test", EvidenceRef: "b.xml#nmap:10.0.0.5:443"})
	if _, err := s.aiReportFindings(ambiguous); err == nil {
		t.Fatal("an ambiguous scopeless AI item must be rejected")
	}
}
```

Make sure `net/http`, `net/http/httptest`, and `encoding/json` are in the test file's imports; they already are for the existing AI test.

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run 'TestAIReportKeepsSameSourceIDOnItsOwnScope|TestAIReportScopelessMatch' -v`
Expected: FAIL. `TestAIReportKeepsSameSourceIDOnItsOwnScope` fails because both outputs map to the last input's scope/evidence. The ambiguous case in `TestAIReportScopelessMatch` fails because no error is returned.

- [ ] **Step 3: Implement.** In `internal/web/report_ai.go`:

(a) Change `const reportPromptVersion = "scanner-report-v1"` to `const reportPromptVersion = "scanner-report-v2"`.

(b) In the prompt string, change the output schema's leading fields from `{"source_id":"exact input source_id","scanner":"exact input scanner",` to `{"source_id":"exact input source_id","scope":"exact input scope","scanner":"exact input scanner",`. Change the final sentence to: `Every output item must use an exact source_id, scope, and evidence_reference from the input.`

(c) Add these helpers below `aiReportFindings`:

```go
// aiFindingKey identifies one input finding for AI validation. A SourceID alone
// is not unique: two host scopes on one IP can both report nmap:<ip>:<port>.
func aiFindingKey(scope, sourceID string) string { return scope + "\x00" + sourceID }

// matchAIFinding resolves an AI output item to exactly one input finding: by
// (scope, source_id), or, when the AI omitted or garbled the scope, by source_id
// alone if that is unambiguous in the chunk. ok is false otherwise, which
// rejects the AI response and forces the deterministic fallback.
func matchAIFinding(allowed map[string]scanner.Finding, bySource map[string][]scanner.Finding, scope, sourceID string) (scanner.Finding, bool) {
	if src, ok := allowed[aiFindingKey(scope, sourceID)]; ok {
		return src, true
	}
	if cands := bySource[sourceID]; len(cands) == 1 {
		return cands[0], true
	}
	return scanner.Finding{}, false
}
```

(d) Replace the `allowed` construction and lookup:

```go
		allowed := map[string]scanner.Finding{}
		bySource := map[string][]scanner.Finding{}
		for _, f := range chunk {
			allowed[aiFindingKey(f.Scope, f.SourceID)] = f
			bySource[f.SourceID] = append(bySource[f.SourceID], f)
		}
		for _, f := range envelope.Findings {
			src, ok := matchAIFinding(allowed, bySource, f.Scope, f.SourceID)
			if !ok {
				return nil, fmt.Errorf("Report AI returned source_id %q (scope %q) that matches no single input finding", f.SourceID, f.Scope)
			}
```

Leave the rest of the loop as is (it already restores `Scope`, `Sources`, `EvidenceRef` from `src`).

(e) Output order: replace the final `sort.SliceStable(out, func(i, j int) bool { return out[i].SourceID < out[j].SourceID })` with a total order, so two same-SourceID findings stay deterministic:

```go
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		return out[i].Scope < out[j].Scope
	})
```

- [ ] **Step 4: Verify pass, then the package**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/web/ -run 'TestAIReport|TestScannerReport' -v && CGO_ENABLED=0 go test ./internal/web/...`
Expected: PASS, including the existing `TestScannerReportAIKeepsMergedTraceAndSeverityFloor`. Its fake AI output has no `scope`, so it now matches by the unique source_id.

- [ ] **Step 5: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/web/ && CGO_ENABLED=0 go vet ./internal/web/...
git add internal/web/report_ai.go internal/web/report_ai_test.go
git commit -m "fix(report): validate AI findings by (scope, source_id)"
```

---

### Task 2: Real OSV severities; unrated placeholders don't drive severity

**Files:**
- Modify: `internal/scanner/parse.go` (`Finding` struct; `parseOSV` ~lines 295-333), `internal/scanner/merge.go` (severity raise in `mergeCrossScanner`), `internal/web/report_ai.go` (severity floor in `aiReportFindings`)
- Test: `internal/scanner/parse_test.go`, `internal/scanner/merge_test.go`, `internal/web/report_ai_test.go`

**Interfaces:**
- Consumes: Task 1's `matchAIFinding` loop (the `src` variable).
- Produces: `Finding.SeverityUnrated bool` (`json:"severity_unrated,omitempty"`); `func osvSeverity(pkgObj map[string]any, v map[string]any, id string) (severity string, cvss float64, rated bool)`.

- [ ] **Step 1: Write failing tests.** Append to `internal/scanner/parse_test.go`:

```go
func TestParseOSVSeverity(t *testing.T) {
	body := `{"results":[{"source":{"path":"/src/go.mod"},"packages":[{"package":{"name":"golang.org/x/net","version":"0.1.0"},` +
		`"groups":[{"ids":["GHSA-aaaa","CVE-2023-44487"],"max_severity":"7.5"}],` +
		`"vulnerabilities":[` +
		`{"id":"GHSA-aaaa","summary":"grouped","aliases":["CVE-2023-44487"]},` +
		`{"id":"GHSA-bbbb","summary":"db-only","database_specific":{"severity":"MODERATE"}},` +
		`{"id":"GO-2024-1","summary":"unrated"}]}]}]}`
	got, err := ParseRun(Run{Scanner: "osv", ArtifactPath: writeFixture(t, "osv.json", body)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %#v", got)
	}
	if got[0].Severity != "high" || got[0].CVSS != 7.5 || got[0].SeverityUnrated {
		t.Errorf("group max_severity: %#v", got[0])
	}
	if got[1].Severity != "medium" || got[1].SeverityUnrated {
		t.Errorf("database_specific MODERATE must be a rated medium: %#v", got[1])
	}
	if got[2].Severity != "medium" || !got[2].SeverityUnrated {
		t.Errorf("no severity data must be an unrated medium placeholder: %#v", got[2])
	}
	if got[0].Evidence != "golang.org/x/net@0.1.0" {
		t.Errorf("evidence = %q, want package@version", got[0].Evidence)
	}
}
```

Append to `internal/scanner/merge_test.go`:

```go
func TestMergeIgnoresUnratedSeverity(t *testing.T) {
	trivyLow := Finding{SourceID: "trivy:CVE-2023-1:go.mod", Scanner: "trivy", Severity: "low", CVE: "CVE-2023-1", Scope: "source:main", Target: "go.mod"}
	osvUnrated := Finding{SourceID: "osv:x:GO-1", Scanner: "osv", Severity: "medium", SeverityUnrated: true, CVE: "CVE-2023-1", Scope: "source:main", Target: "go.mod"}
	if out := mergeCrossScanner([]Finding{trivyLow, osvUnrated}); len(out) != 1 || out[0].Severity != "low" {
		t.Fatalf("unrated contributor must not raise severity, got %#v", out)
	}
	out := mergeCrossScanner([]Finding{osvUnrated, trivyLow})
	if len(out) != 1 || out[0].Severity != "low" || out[0].SeverityUnrated {
		t.Fatalf("a rated contributor must replace an unrated primary's placeholder, got %#v", out)
	}
}
```

Append to `internal/web/report_ai_test.go`:

```go
func TestAIReportUnratedSeverityIsNotAFloor(t *testing.T) {
	s := aiServer(t, aiProvider(t, []map[string]any{{"source_id": "osv:x:GO-1", "scanner": "osv", "title": "t", "severity": "low", "explanation": "e", "evidence_reference": "x", "impact": "i", "remediation": "r"}}))
	out, err := s.aiReportFindings([]scanner.Finding{{SourceID: "osv:x:GO-1", Scanner: "osv", Severity: "medium", SeverityUnrated: true, Scope: "source:main", EvidenceRef: "osv.json#osv:x:GO-1"}})
	if err != nil || len(out) != 1 || out[0].Severity != "low" {
		t.Fatalf("AI may rate an unrated finding freely: out=%#v err=%v", out, err)
	}
}
```

- [ ] **Step 2: Verify failure**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestParseOSVSeverity|TestMergeIgnoresUnratedSeverity' -v; CGO_ENABLED=0 go test ./internal/web/ -run TestAIReportUnratedSeverityIsNotAFloor -v`
Expected: build FAIL (`unknown field SeverityUnrated`).

- [ ] **Step 3: Add the field** to `Finding` (parse.go), after `CVSS`:

```go
	// SeverityUnrated marks a placeholder severity: the scanner gave no rating
	// (e.g. an OSV entry with no CVSS or database severity). Merge and the AI
	// severity floor ignore it rather than treat the placeholder as a rating.
	SeverityUnrated bool `json:"severity_unrated,omitempty"`
```

- [ ] **Step 4: Implement OSV severity.** In `parseOSV`, replace the finding construction with:

```go
				sev, cvss, rated := osvSeverity(pkgObj, v, id)
				out = append(out, Finding{
					SourceID:        "osv:" + name + ":" + id,
					Scanner:         "osv",
					Title:           firstNonEmpty(id, name),
					Severity:        sev,
					SeverityUnrated: !rated,
					CVSS:            cvss,
					Target:          name,
					Endpoint:        srcPath,
					Description:     str(v["summary"]),
					Evidence:        osvPackageLabel(pkg),
					CVE:             cve,
				})
```

Add below `parseOSV`:

```go
// osvSeverity rates one OSV vulnerability. osv-scanner reports a numeric CVSS
// max_severity per alias group; GHSA records also carry a textual
// database_specific.severity. With neither, the finding is an unrated "medium"
// placeholder.
func osvSeverity(pkgObj map[string]any, v map[string]any, id string) (string, float64, bool) {
	for _, gv := range array(pkgObj["groups"]) {
		g, _ := gv.(map[string]any)
		for _, gid := range array(g["ids"]) {
			if str(gid) != id {
				continue
			}
			if score, err := strconv.ParseFloat(str(g["max_severity"]), 64); err == nil && score > 0 {
				return cvssSeverity(score, ""), score, true
			}
		}
	}
	db, _ := v["database_specific"].(map[string]any)
	switch strings.ToLower(str(db["severity"])) {
	case "critical":
		return "critical", 0, true
	case "high":
		return "high", 0, true
	case "moderate", "medium":
		return "medium", 0, true
	case "low":
		return "low", 0, true
	}
	return "medium", 0, false
}

func osvPackageLabel(pkg map[string]any) string {
	name, version := str(pkg["name"]), str(pkg["version"])
	if version == "" {
		return name
	}
	return name + "@" + version
}
```

- [ ] **Step 5: Unrated-aware merge raise.** In `mergeCrossScanner` (merge.go), replace

```go
		if severityRank(f.Severity) > severityRank(m.Severity) {
			m.Severity = f.Severity
		}
```

with

```go
		// An unrated placeholder never raises a rating; a rated contributor
		// replaces an unrated primary's placeholder outright.
		switch {
		case f.SeverityUnrated:
		case m.SeverityUnrated:
			m.Severity, m.SeverityUnrated = f.Severity, false
		case severityRank(f.Severity) > severityRank(m.Severity):
			m.Severity = f.Severity
		}
```

- [ ] **Step 6: Unrated-aware AI floor.** In `aiReportFindings` (report_ai.go), change the floor condition to skip unrated sources:

```go
			if srcSev := normalizeSeverityBucket(src.Severity); !src.SeverityUnrated && severityRankValue(srcSev) > severityRankValue(f.Severity) {
				f.Severity = srcSev
			}
```

Update the comment above it to say an unrated placeholder is not a floor.

- [ ] **Step 7: Verify pass + suites**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/...`
Expected: PASS. `TestParseOSVFindings` still passes: its SourceID and CVE are unchanged.

- [ ] **Step 8: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ internal/web/ && CGO_ENABLED=0 go vet ./internal/scanner/... ./internal/web/...
git add internal/scanner/parse.go internal/scanner/parse_test.go internal/scanner/merge.go internal/scanner/merge_test.go internal/web/report_ai.go internal/web/report_ai_test.go
git commit -m "feat(scanner): rate OSV findings and ignore unrated placeholders in merge and AI floor"
```

---

### Task 3: Source-scope paths relative to the checkout; file-aware merge

**Files:**
- Modify: `internal/scanner/parse.go` (`ParseRuns` loop; `parseOSV` Target), `internal/scanner/merge.go` (merge key)
- Test: `internal/scanner/merge_test.go`, `internal/scanner/parse_test.go`

**Interfaces:**
- Consumes: Task 2's `parseOSV` literal (this task changes its `Target`).
- Produces: `func relativeToRoot(p, root string) string`, `func mergeLocation(f Finding) string`. On source scopes, every source parser's `Target` is the file path relative to the checkout (trivy: result target; osv: manifest path; semgrep/gitleaks: file), and `Endpoint` is relative too.

Background: trivy reports `Target` relative to the scanned dir (e.g. `web/package-lock.json`). osv-scanner, semgrep and gitleaks, run on the absolute checkout path, report absolute paths (e.g. `/…/source/checkout/web/package-lock.json`). Today the merge key ignores location, so the first trivy and first osv report of a CVE pair up even when they came from different lockfiles. Absolute checkout paths also leak into the report.

- [ ] **Step 1: Write failing tests.** Append to `internal/scanner/parse_test.go`:

```go
func TestRelativeToRoot(t *testing.T) {
	cases := []struct{ p, root, want string }{
		{"/scan/src/web/package-lock.json", "/scan/src", "web/package-lock.json"},
		{"/scan/src/app.go:12", "/scan/src/", "app.go:12"},
		{"web/package-lock.json", "/scan/src", "web/package-lock.json"},
		{"/other/x.go", "/scan/src", "/other/x.go"},
		{"/scan/srcfoo/x.go", "/scan/src", "/scan/srcfoo/x.go"},
		{"/scan/src/x.go", "", "/scan/src/x.go"},
	}
	for _, c := range cases {
		if got := relativeToRoot(c.p, c.root); got != c.want {
			t.Errorf("relativeToRoot(%q, %q) = %q, want %q", c.p, c.root, got, c.want)
		}
	}
}

func TestParseRunsSourcePathsAndFileAwareMerge(t *testing.T) {
	root := t.TempDir()
	trivy := writeFixture(t, "trivy.json", `{"Results":[{"Target":"web/package-lock.json","Vulnerabilities":[{"VulnerabilityID":"CVE-2023-1111","PkgName":"lib","Severity":"HIGH"}]}]}`)
	osv := writeFixture(t, "osv.json", `{"results":[`+
		`{"source":{"path":"`+root+`/web/package-lock.json"},"packages":[{"package":{"name":"lib"},"vulnerabilities":[{"id":"GHSA-1","aliases":["CVE-2023-1111"]}]}]},`+
		`{"source":{"path":"`+root+`/api/package-lock.json"},"packages":[{"package":{"name":"lib"},"vulnerabilities":[{"id":"GHSA-1","aliases":["CVE-2023-1111"]}]}]}]}`)
	findings, errs := ParseRuns([]Run{
		{Scanner: "trivy", Scope: "source:main", Target: root, Status: "completed", ArtifactPath: trivy},
		{Scanner: "osv", Scope: "source:main", Target: root, Status: "completed", ArtifactPath: osv},
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(findings) != 2 {
		t.Fatalf("want web merged (trivy+osv) and api separate, got %d: %#v", len(findings), findings)
	}
	web, api := findings[0], findings[1]
	if web.Target != "web/package-lock.json" || len(web.Sources) != 2 {
		t.Fatalf("web finding = %#v", web)
	}
	if api.Scanner != "osv" || api.Target != "api/package-lock.json" || api.Endpoint != "api/package-lock.json" || len(api.Sources) != 0 {
		t.Fatalf("api finding must stay separate with relative paths, got %#v", api)
	}
	if !strings.HasPrefix(api.SourceID, "osv:lib:GHSA-1") {
		t.Fatalf("SourceID must be unchanged, got %q", api.SourceID)
	}
}
```

Make sure `strings` is imported in parse_test.go.

- [ ] **Step 2: Verify failure**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run 'TestRelativeToRoot|TestParseRunsSourcePathsAndFileAwareMerge' -v`
Expected: build FAIL (`undefined: relativeToRoot`).

- [ ] **Step 3: OSV Target is the manifest.** In `parseOSV`, change `Target: name,` to `Target: srcPath,`. The package now lives in `Evidence` (from Task 2) and in the SourceID. This gives every source parser the same `Target` meaning: the file.

- [ ] **Step 4: Relativize in `ParseRuns`.** Add below `FindingScope`:

```go
// relativeToRoot rewrites a finding path under root (the source checkout) to be
// relative to it, so the report never shows the internal checkout path and
// scanners that report absolute vs relative paths agree. Paths outside root, and
// any path when root is empty, are returned unchanged. p may carry a ":line"
// suffix.
func relativeToRoot(p, root string) string {
	root = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(root)), "/")
	if root == "" || root == "." {
		return p
	}
	if rest, ok := strings.CutPrefix(filepath.ToSlash(p), root+"/"); ok {
		return rest
	}
	return p
}
```

(`filepath.Clean("")` returns `"."`, so the `root == "."` test is what makes an empty root return `p` unchanged.)

In the `ParseRuns` loop, after `scope := FindingScope(run)`, add:

```go
		// Source-scope paths become relative to the checkout (run.Target). The
		// SourceID and EvidenceRef keep the native path: they are trace keys.
		sourceRoot := ""
		if strings.HasPrefix(scope, "source:") {
			sourceRoot = run.Target
		}
```

and inside the per-finding loop, after setting `Scope`:

```go
			if sourceRoot != "" {
				parsed[i].Target = relativeToRoot(parsed[i].Target, sourceRoot)
				parsed[i].Endpoint = relativeToRoot(parsed[i].Endpoint, sourceRoot)
			}
```

- [ ] **Step 5: File-aware merge key.** In merge.go, add:

```go
// mergeLocation is the extra merge-key component that keeps one CVE in two
// files of a source tree apart: the file (Target) on source scopes, nothing on
// host scopes (where different scanners describe the location differently —
// a URL vs a port — so the scope alone identifies the asset).
func mergeLocation(f Finding) string {
	if strings.HasPrefix(f.Scope, "source:") {
		return filepath.ToSlash(filepath.Clean(f.Target))
	}
	return ""
}
```

Change `key := f.Scope + "\x00" + cve` to `key := f.Scope + "\x00" + cve + "\x00" + mergeLocation(f)`, and add `"path/filepath"` to merge.go's imports. Update the `mergeCrossScanner` doc comment to mention the file on source scopes.

- [ ] **Step 6: Verify pass + suites**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/...`
Expected: PASS. If an existing test asserted an osv `Target` equal to the package name, update it to the manifest path. That is an intentional change; don't weaken the assertion. `TestMergeCrossScannerCollapsesSameCVEOnSameScope` and the "same scanner twice" case are host/source tests with matching or absent targets, so they must stay green unchanged.

- [ ] **Step 7: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ && CGO_ENABLED=0 go vet ./internal/scanner/...
git add internal/scanner/parse.go internal/scanner/parse_test.go internal/scanner/merge.go internal/scanner/merge_test.go
git commit -m "fix(scanner): keep source findings relative to the checkout and merge CVEs per file"
```

---

### Task 4: Source origin label, fitted PDF labels, manifest v2, docs

**Files:**
- Modify: `internal/scanner/source.go`, `internal/scanner/pipeline.go` (line ~210), `internal/web/report_scopes.go`, `internal/web/report_coverage.go`, `internal/web/report.go` (~line 1139), `internal/web/report_ai.go` (manifest `SchemaVersion`, ~line 95), `README.md` (Persistence section)
- Test: `internal/scanner/source_test.go`, `internal/web/report_scopes_test.go`, `internal/web/report_coverage_test.go`, `internal/web/report_ai_test.go`

**Interfaces:**
- Produces: `func LoadSourceScope(scanDir string) (Scope, bool)` (scanner); `reportScope.Origin string` (`json:"origin,omitempty"`); `func sourceOrigin(sc scanner.Scope) string`, `func redactURL(raw string) string`, `func fitPDFText(pdf *fpdf.Fpdf, s string, w float64) string` (web).

- [ ] **Step 1: Write failing tests.** Append to `internal/scanner/source_test.go`:

```go
func TestSourceScopePersistedByPipeline(t *testing.T) {
	scanDir, src := t.TempDir(), t.TempDir()
	if _, ok := LoadSourceScope(scanDir); ok {
		t.Fatal("no file yet must report ok=false")
	}
	p := &Pipeline{}
	p.Run(context.Background(), Request{Target: "example.test", ScanDir: scanDir, Artifact: Artifact{Kind: "filesystem", Ref: src}}, nil, nil)
	got, ok := LoadSourceScope(scanDir)
	if !ok || got.ID != "source:main" || got.Target != src || got.Source.Provenance != "provided:filesystem" {
		t.Fatalf("persisted source scope = %#v ok=%v", got, ok)
	}
}
```

(Add `"context"` to the imports if it is missing. A `Pipeline` with no runners and a nil recon function scans nothing, so this test exercises only scope resolution and persistence.)

Append to `internal/web/report_scopes_test.go`:

```go
func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://user:tok@github.com/a/b.git": "https://github.com/a/b.git",
		"https://github.com/a/b.git":          "https://github.com/a/b.git",
		"git@github.com:a/b.git":              "git@github.com:a/b.git",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildReportScopesSourceOrigin(t *testing.T) {
	dir := t.TempDir()
	writeSourceScope := func(sc scanner.Scope) {
		data, _ := json.Marshal(sc)
		p := filepath.Join(dir, "scanner-output", "source-scope.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runs := []scanner.Run{{Scanner: "trivy", Scope: "source:main", Target: "/scans/x/source/checkout", Status: "completed"}}
	writeSourceScope(scanner.Scope{ID: "source:main", Kind: scanner.ScopeSource, Target: "/scans/x/source/checkout", Source: scanner.SourceRef{Path: "/scans/x/source/checkout", Provenance: "clone:https://user:tok@github.com/a/b.git"}})
	if got := buildReportScopes(dir, runs); len(got) != 1 || got[0].Origin != "https://github.com/a/b.git" || reportScopeLabel(got[0]) != "SOURCE CODE  https://github.com/a/b.git" {
		t.Fatalf("clone origin: %#v", got)
	}
	writeSourceScope(scanner.Scope{ID: "source:main", Kind: scanner.ScopeSource, Target: "/home/me/app", Source: scanner.SourceRef{Path: "/home/me/app", Provenance: "provided:filesystem"}})
	if got := buildReportScopes(dir, runs); got[0].Origin != "/home/me/app" {
		t.Fatalf("provided origin: %#v", got)
	}
	if got := buildReportScopes(t.TempDir(), runs); got[0].Origin != "" || reportScopeLabel(got[0]) != "SOURCE CODE  /scans/x/source/checkout" {
		t.Fatalf("legacy scan without source-scope.json must keep the old label: %#v", got)
	}
}
```

(`encoding/json`, `os`, `path/filepath` are already imported by that test file for `writeReconScopes`.)

Append to `internal/web/report_coverage_test.go`:

```go
func TestFitPDFText(t *testing.T) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 9)
	short := "HOST  a.test  [web]"
	if got := fitPDFText(pdf, short, 182); got != short {
		t.Fatalf("short label changed: %q", got)
	}
	long := "HOST  " + strings.Repeat("very-long-subdomain.", 20) + "example.test  [web, server]"
	got := fitPDFText(pdf, long, 182)
	if !strings.HasSuffix(got, "...") || pdf.GetStringWidth(got) > 182 {
		t.Fatalf("long label not fitted: %q (width %.1f)", got, pdf.GetStringWidth(got))
	}
}
```

(Add `"strings"` and `"github.com/go-pdf/fpdf"` to that file's imports.)

In `internal/web/report_ai_test.go`, inside the existing `TestScannerReportGroupsByScopeAndMergesCVE`, add right after `manifest` is unmarshalled:

```go
	if manifest.SchemaVersion != 2 || manifest.PromptVersion != "scanner-report-v2" {
		t.Fatalf("manifest version = %d / %q, want 2 / scanner-report-v2", manifest.SchemaVersion, manifest.PromptVersion)
	}
```

- [ ] **Step 2: Verify failure**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/ -run TestSourceScopePersistedByPipeline -v; CGO_ENABLED=0 go test ./internal/web/ -run 'TestRedactURL|TestBuildReportScopesSourceOrigin|TestFitPDFText|TestScannerReportGroupsByScopeAndMergesCVE' -v`
Expected: build FAIL (`undefined: LoadSourceScope`, `redactURL`, `fitPDFText`).

- [ ] **Step 3: Persist the source scope.** Append to `internal/scanner/source.go` (add `"encoding/json"` to its imports if missing):

```go
func sourceScopePath(scanDir string) string {
	return filepath.Join(scanDir, "scanner-output", "source-scope.json")
}

// saveSourceScope records the resolved source scope (including its provenance)
// so the report can label it by origin rather than by the local checkout path.
// A write failure is non-fatal.
func saveSourceScope(scanDir string, sc Scope) {
	if strings.TrimSpace(scanDir) == "" {
		return
	}
	path := sourceScopePath(scanDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// LoadSourceScope returns the source scope persisted for a scan. ok is false for
// scans that predate it or whose file is unreadable.
func LoadSourceScope(scanDir string) (Scope, bool) {
	data, err := os.ReadFile(sourceScopePath(scanDir))
	if err != nil {
		return Scope{}, false
	}
	var sc Scope
	if err := json.Unmarshal(data, &sc); err != nil || sc.ID == "" {
		return Scope{}, false
	}
	return sc, true
}
```

In `internal/scanner/pipeline.go`, replace `scopes = append(scopes, resolveSourceScope(ctx, req, p.Config, safeEmit))` with:

```go
	sourceScope := resolveSourceScope(ctx, req, p.Config, safeEmit)
	saveSourceScope(req.ScanDir, sourceScope)
	scopes = append(scopes, sourceScope)
```

(Keep the existing comment above it about appending before `results` is allocated.)

- [ ] **Step 4: Origin on the report scope.** In `internal/web/report_scopes.go`:
- Add `"net/url"` to the imports.
- Add `Origin string \`json:"origin,omitempty"\`` to `reportScope`, after `Target`.
- In `buildReportScopes`, right after the `evidence` map is filled, load the source scope once:

```go
	sourceScope, hasSourceScope := scanner.LoadSourceScope(scanDir)
```

and in the `if strings.HasPrefix(id, "source:") {` branch, after `rs.Kind = ...`:

```go
				if hasSourceScope && sourceScope.ID == id {
					rs.Origin = sourceOrigin(sourceScope)
				}
```

Add these helpers:

```go
// sourceOrigin is how the report names a source scope: the repository it was
// cloned from (credentials removed), or the directory the operator provided.
// Empty when no source resolved.
func sourceOrigin(sc scanner.Scope) string {
	prov := sc.Source.Provenance
	if u, ok := strings.CutPrefix(prov, "clone:"); ok {
		return redactURL(u)
	}
	if prov == "provided:filesystem" {
		return sc.Source.Path
	}
	return ""
}

// redactURL drops any userinfo (e.g. a token in https://user:tok@host/...) from
// a URL. Non-URL forms such as scp-style git@host:path are returned unchanged.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
```

- [ ] **Step 5: Origin-aware label + fitted text.** In `internal/web/report_coverage.go`, change the source branch of `reportScopeLabel` to:

```go
		return "SOURCE CODE  " + firstNonBlank(sc.Origin, sc.Target, "none provided")
```

Add:

```go
// fitPDFText truncates s with "..." so it fits width w (mm) in the pdf's current
// font. Call it after SetFont. Labels are single-line cells, so an over-long
// hostname would otherwise overflow the page.
func fitPDFText(pdf *fpdf.Fpdf, s string, w float64) string {
	if pdf.GetStringWidth(s) <= w {
		return s
	}
	runes := []rune(s)
	for len(runes) > 0 && pdf.GetStringWidth(string(runes)+"...") > w {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "..."
}
```

In `drawScanCoverage`, change `pdf.CellFormat(182, 6, reportScopeLabel(sc), "", 1, "L", false, 0, "")` to `pdf.CellFormat(182, 6, fitPDFText(pdf, reportScopeLabel(sc), 182), "", 1, "L", false, 0, "")`.

In `internal/web/report.go`, change the summary group row `pdf.CellFormat(186, 6, firstNonBlank(scopeLabels[v.Scope], v.Scope, "UNSCOPED"), "", 1, "L", false, 0, "")` to `pdf.CellFormat(186, 6, fitPDFText(pdf, firstNonBlank(scopeLabels[v.Scope], v.Scope, "UNSCOPED"), 186), "", 1, "L", false, 0, "")`. It already sits after its `SetFont` call.

- [ ] **Step 6: Manifest v2.** In `generateScannerReport` (report_ai.go), change `reportManifest{SchemaVersion: 1,` to `reportManifest{SchemaVersion: 2,`.

- [ ] **Step 7: README.** In the `## Persistence` section, after the sentence ending "…persisted at `scanner-output/recon-scopes.json`.", add: `The resolved source scope, with its provenance (clone URL or provided directory), is persisted at \`scanner-output/source-scope.json\`, so the report can name the source by origin.` In the `report.json` sentence, change "`report.json` records" to "`report.json` (manifest schema 2) records". Leave the rest of that sentence unchanged.

- [ ] **Step 8: Verify pass + suites**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/...`
Expected: PASS.

- [ ] **Step 9: Gate + commit**

```bash
cd /Users/acho/Desktop/cyber/xalgorix && gofmt -l internal/scanner/ internal/web/ && CGO_ENABLED=0 go vet ./internal/scanner/... ./internal/web/...
git add internal/scanner/source.go internal/scanner/source_test.go internal/scanner/pipeline.go internal/web/report_scopes.go internal/web/report_scopes_test.go internal/web/report_coverage.go internal/web/report_coverage_test.go internal/web/report.go internal/web/report_ai.go internal/web/report_ai_test.go README.md
git commit -m "feat(report): label source by origin, fit PDF scope labels, manifest v2"
```

---

### Task 5: Whole-tree verification

**Files:** none expected.

- [ ] **Step 1: Build + vet + gofmt**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go build ./... && gofmt -l internal/ cmd/ && CGO_ENABLED=0 go vet ./internal/... ./cmd/...`
Expected: only the pre-existing `internal/agent/hooks.go` / `hooks_test.go` gofmt drift.

- [ ] **Step 2: Full suite minus darwin-only packages**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go list ./... | grep -vE '/internal/(sandbox|tools/fileedit|tools/notes|tools/terminal|resources|tools/browser|tools/python)$' | CGO_ENABLED=0 xargs go test -timeout 300s -count=1; echo EXIT=$?`
Expected: `EXIT=0`. (The excluded packages fail or hang only on macOS; see the darwin testing notes.)

- [ ] **Step 3: Affected suites twice**

Run: `cd /Users/acho/Desktop/cyber/xalgorix && CGO_ENABLED=0 go test ./internal/scanner/... ./internal/web/... -count=2`
Expected: PASS twice.

- [ ] **Step 4: Commit any fixups** (skip if none), with no Claude attribution line.

---

## Self-Review

**Coverage of the four follow-ups:**
- Follow-up 1 (AI host labels): Task 1. Validation uses `(scope, source_id)` with an unambiguous-scopeless fallback; ambiguous output is rejected so the report falls back deterministically; output order is total.
- Follow-up 2 (OSV severity): Task 2. `groups[].max_severity`, then `database_specific.severity`, then an unrated placeholder; the merge and the AI floor ignore unrated placeholders.
- Follow-up 3 (per-file source merge): Task 3. Paths are relative to the checkout, and the merge key includes the file on source scopes. OSV `Target` becomes the manifest, matching trivy/semgrep/gitleaks.
- Follow-up 4 (PDF/manifest polish): Task 4. Persisted source scope, origin label with credential redaction, `fitPDFText` for both label cells, manifest v2. Prompt v2 comes from Task 1.

**Placeholder scan:** every code step has complete code, and every README edit has exact text.

**Type consistency:**
- `Finding.SeverityUnrated` (Task 2) is read in merge.go (Task 2) and report_ai.go (Task 2).
- `matchAIFinding` (Task 1) returns the `src` that Task 2's floor reads.
- `LoadSourceScope` returns `scanner.Scope`, whose `Source.Provenance` values `"clone:<url>"` / `"provided:filesystem"` match `resolveSourceScope` in source.go.
- `reportScope.Origin` (Task 4) is read by `reportScopeLabel` (Task 4).

**Risks for the executor:**
- (a) Task 3 changes osv `Target` and source-scope `Target`/`Endpoint` values. Any test pinning the old absolute or package-name values must be updated to the new intended values, never weakened.
- (b) Task 4's pipeline test uses a zero-value `Pipeline`. If `Run` needs a non-nil emit or config, pass `func(Event) {}` / `Config{}` rather than changing production code.
- (c) Task 1's scopeless fallback accepts a unique source_id, so the existing AI test, whose fake output has no scope, keeps passing. Don't remove that fallback to make a test stricter.

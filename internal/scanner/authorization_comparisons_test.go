package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func comparisonFixture(t *testing.T, labURL string) (Request, Config) {
	t.Helper()
	directory := t.TempDir()
	raw, _ := json.Marshal(AuthorizationResourceFixture{URL: labURL + "/api/items/1", ResponseMarker: "CONTROLLED_RESOURCE_1"})
	hash := sha256.Sum256(raw)
	ref := hex.EncodeToString(hash[:])
	if err := os.WriteFile(filepath.Join(directory, ref+".body"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	origin, _ := assessment.ParseApprovedOrigin("app", labURL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	req := Request{Target: labURL + "/", ScanDir: t.TempDir(), Scope: "app:app", AttemptID: "attempt", PlanFingerprint: "accepted", AppScope: &scope, TypedAssessment: true, APIFixtureDir: directory, APIEndpoints: []APIEndpoint{{OperationID: "getItem", TargetID: "app", Origin: labURL, Path: "/api/items/1", Method: "GET", Source: "openapi", Resolved: true, Eligible: true}}}
	for _, role := range []string{"owner", "reader"} {
		req.AuthContexts = append(req.AuthContexts, AuthContext{ID: AuthenticationContextID("app", role), TargetID: "app", Identity: role, Role: role, State: assessment.StateVerified, Headers: []string{"Authorization: Bearer " + role + "-secret"}, Refresh: func(_ context.Context, headers []string) ([]string, error) { return headers, nil }})
		expected := "allow"
		if role == "reader" {
			expected = "deny"
		}
		req.AuthorizationExpectations = append(req.AuthorizationExpectations, assessment.AuthorizationExpectation{OperationID: "getItem", Identity: role, Expect: expected, ResourceFixtureRef: ref})
	}
	surface := NewSeedAttackSurface("app:app", labURL+"/")
	addAuthorizationRequestVariants(surface, req)
	req.EndpointTargets = DispatchTargets(surface, "apichecks", 100)
	req.InputRequests = BuildScannerInputs(surface, req, "apichecks")
	req.Inventory = surface
	return req, Config{Budget: NewAssessmentBudget(1000, 100, time.Minute)}
}

func TestAuthorizationComparisonsUseIsolatedRolesAndControlledResourceEvidence(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "role-violation"}[vulnerable], func(t *testing.T) {
			var authHeaders []string
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authHeaders = append(authHeaders, r.Header.Get("Authorization"))
				if r.Method != "GET" || len(r.Header.Values("Authorization")) != 1 {
					t.Error("unsafe or mixed-identity request")
				}
				if r.Header.Get("Authorization") == "Bearer reader-secret" && !vulnerable {
					http.Error(w, "denied", 403)
					return
				}
				w.Write([]byte(`{"resource":"CONTROLLED_RESOURCE_1","token":"private-response-value"}`))
			}))
			defer lab.Close()
			req, cfg := comparisonFixture(t, lab.URL)
			var findings []Finding
			run := Run{Scanner: "apichecks"}
			checked, gaps, err := runAuthorizationComparisons(t.Context(), req, cfg, &run, func(finding Finding) error { findings = append(findings, finding); return nil })
			if err != nil || checked != 2 || gaps != 0 || len(run.AuthorizationResults) != 2 {
				t.Fatalf("comparison: %d %d %v %+v", checked, gaps, err, run.AuthorizationResults)
			}
			if len(authHeaders) != 2 || authHeaders[0] != "Bearer owner-secret" || authHeaders[1] != "Bearer reader-secret" {
				t.Fatalf("credential isolation: %v", authHeaders)
			}
			expectedFindings := 0
			if vulnerable {
				expectedFindings = 1
			}
			if len(findings) != expectedFindings {
				t.Fatalf("findings: %+v", findings)
			}
			if vulnerable && (findings[0].CWE != "CWE-863" || findings[0].Endpoint != lab.URL+"/api/items/1" || findings[0].EvidenceRef == "") {
				t.Fatalf("missing native location/evidence: %+v", findings[0])
			}
			serialized, _ := json.Marshal(run)
			evidence, _ := os.ReadFile(run.CoverageEventsPath)
			for _, secret := range []string{"owner-secret", "reader-secret", "private-response-value"} {
				if strings.Contains(string(serialized)+string(evidence), secret) {
					t.Fatal("comparison secret persisted")
				}
			}
			events, err := ReadCoverageEvents(run.CoverageEventsPath)
			if err != nil {
				t.Fatal(err)
			}
			observed := map[string]bool{}
			for _, event := range events {
				if event.Kind == "observed" {
					for _, id := range event.EndpointIDs {
						observed[id] = true
					}
				}
			}
			if len(observed) != 2 {
				t.Fatalf("role variants lost native receipts: %+v", events)
			}
		})
	}
}

func TestAuthorizationComparisonNeverInfersAccessFromGeneric200OrRedirect(t *testing.T) {
	for _, mode := range []string{"generic-200", "redirect", "missing-allow-baseline"} {
		t.Run(mode, func(t *testing.T) {
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "/login", 302)
					return
				}
				if mode == "missing-allow-baseline" && r.Header.Get("Authorization") == "Bearer reader-secret" {
					w.Write([]byte("CONTROLLED_RESOURCE_1"))
					return
				}
				w.Write([]byte("public login page"))
			}))
			defer lab.Close()
			req, cfg := comparisonFixture(t, lab.URL)
			run := Run{Scanner: "apichecks"}
			var findings []Finding
			_, gaps, err := runAuthorizationComparisons(t.Context(), req, cfg, &run, func(f Finding) error { findings = append(findings, f); return nil })
			if err != nil || gaps == 0 || len(findings) != 0 {
				t.Fatalf("invented proof: %v gaps=%d findings=%+v", err, gaps, findings)
			}
		})
	}
}

func TestAuthorizationComparisonsRefuseAliasesWritesAndUnselectedInputs(t *testing.T) {
	for _, mode := range []string{"alias", "write", "excluded", "unselected", "expired", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			hits := 0
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte("CONTROLLED_RESOURCE_1")) }))
			defer lab.Close()
			req, cfg := comparisonFixture(t, lab.URL)
			switch mode {
			case "alias":
				req.Target = "http://different.test/"
			case "wrong-target":
				for i := range req.AuthContexts {
					req.AuthContexts[i].TargetID = "other-target"
				}
			case "write":
				req.APIEndpoints[0].Method = "POST"
			case "excluded":
				scope := assessment.NewAppScope(req.AppScope.Origins(), assessment.Exclusion{Method: "GET", PathPattern: "/api/items/*"})
				req.AppScope = &scope
			case "unselected":
				req.InputRequests = nil
			case "expired":
				for i := range req.AuthContexts {
					req.AuthContexts[i].Refresh = func(context.Context, []string) ([]string, error) { return nil, context.Canceled }
				}
			}
			run := Run{Scanner: "apichecks"}
			checked, gaps, err := runAuthorizationComparisons(t.Context(), req, cfg, &run, func(Finding) error { t.Fatal("unexpected finding"); return nil })
			if err != nil || checked != 0 || gaps != 2 || hits != 0 {
				t.Fatalf("scope/auth gate failed: hits=%d checked=%d gaps=%d err=%v", hits, checked, gaps, err)
			}
		})
	}
}

func TestAPICheckRunnerPersistsAuthorizationFindingAndProof(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "denied", 401)
			return
		}
		w.Write([]byte("CONTROLLED_RESOURCE_1"))
	}))
	defer lab.Close()
	req, cfg := comparisonFixture(t, lab.URL)
	run := (apiChecksRunner{}).Run(t.Context(), req, cfg, nil)
	if run.Status != "completed" || len(run.AuthorizationResults) != 2 {
		t.Fatalf("run: %+v", run)
	}
	findings, err := parseAPIChecks(run.ArtifactPath)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings: %+v, %v", findings, err)
	}
	encoded, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	var restored Run
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	proof := BuildCoverageProof([]AttackSurface{*req.Inventory}, []Run{restored})
	if len(proof.AuthorizationResults) != 2 || proof.AuthorizationResults[1].Status != "mismatch" {
		t.Fatalf("proof: %+v", proof.AuthorizationResults)
	}
}

func TestAPICheckRunnerUnresolvedAuthorizationIsPartial(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "denied", 401) }))
	defer lab.Close()
	req, cfg := comparisonFixture(t, lab.URL)
	req.InputRequests = nil
	run := (apiChecksRunner{}).Run(t.Context(), req, cfg, nil)
	if run.Outcome != "PARTIAL" || len(run.AuthorizationResults) != 2 {
		t.Fatalf("lost role gaps: %+v", run)
	}
}

func TestAssessmentExecutorRoutesAuthorizationContextsOnFirstAttempt(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "denied", 401)
			return
		}
		if r.Header.Get("Authorization") == "Bearer reader-secret" {
			http.Error(w, "denied", 403)
			return
		}
		w.Write([]byte("CONTROLLED_RESOURCE_1"))
	}))
	defer lab.Close()
	req, cfg := comparisonFixture(t, lab.URL)
	cfg.KatanaPath = "/nonexistent/katana"
	cfg.AssessmentAuthContexts = req.AuthContexts
	cfg.APIFixtureDir = req.APIFixtureDir
	cfg.WebMaxEndpoints = 100
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: req.Target}
	plan := AssessmentPlan{Fingerprint: "role-first-attempt", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1", Targets: []assessment.Target{target}, Types: []assessment.Type{assessment.TypeAPI}, AuthorizationExpectations: req.AuthorizationExpectations}, APIEndpoints: req.APIEndpoints, Jobs: []PlanJob{{ID: "katana-app", Scanner: "katana", Variant: "katana", TargetID: "app", Target: req.Target, State: PlanSelected, AssessmentType: assessment.TypeAPI}, {ID: "apichecks-app", Scanner: "apichecks", Variant: "apichecks", TargetID: "app", Target: req.Target, State: PlanSelected, AssessmentType: assessment.TypeAPI}}}
	pipeline := Pipeline{Config: cfg}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	for _, run := range runs {
		if run.Scanner == "apichecks" {
			if len(run.AuthorizationResults) != 2 || run.AuthorizationResults[0].Status != "matched" || run.AuthorizationResults[1].Status != "matched" {
				t.Fatalf("first attempt lost authorization configuration: %+v", run)
			}
			return
		}
	}
	t.Fatalf("no API run: %+v", runs)
}

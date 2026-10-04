package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestAPIChecksUseScopedUnauthenticatedGETAndRecordFindings(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	var authorization []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		authorization = append(authorization, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()
	endpointURL := server.URL + "/api/items?sample=1"
	approved, err := assessment.ParseApprovedOrigin("app", server.URL+"/api")
	if err != nil {
		t.Fatal("parse approved fixture origin:", err)
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{approved})
	var guardAddresses []string
	guard := func(_ string, addresses []string) (bool, string) {
		guardAddresses = append(guardAddresses, addresses...)
		return false, ""
	}
	req := Request{
		Target: server.URL + "/api/", Scope: "app:app", ScanDir: t.TempDir(), TypedAssessment: true,
		AppScope: &scope, EndpointTargets: []string{endpointURL},
		APIEndpoints: []APIEndpoint{{Method: http.MethodGet, Path: "/items", Origin: server.URL, Source: "openapi", Resolved: true, Eligible: true, SecuritySchemes: []string{"bearerAuth"}}},
	}
	run := (apiChecksRunner{}).Run(context.Background(), req, Config{Budget: NewAssessmentBudget(20, 10, time.Minute), ScopeGuard: guard}, nil)
	if run.Status != "completed" || len(run.APIEndpointResults) != 1 || run.APIEndpointResults[0].Status != "checked" {
		t.Fatalf("run=%+v", run)
	}
	if !slices.Contains(guardAddresses, "127.0.0.1") && !slices.Contains(guardAddresses, "::1") {
		t.Fatalf("scope guard did not receive resolved addresses: %v", guardAddresses)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(methods, []string{http.MethodGet}) || len(authorization) != 1 || authorization[0] != "" {
		t.Fatalf("requests were not credential-free GET only: methods=%v authorization=%v", methods, authorization)
	}
	findings, err := ParseRun(run)
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if !slices.ContainsFunc(findings, func(f Finding) bool { return f.RuleID == "api-auth-not-enforced" && f.CWE == "CWE-862" }) || !slices.ContainsFunc(findings, func(f Finding) bool { return f.RuleID == "api-cors-credentialed-origin" && f.CWE == "CWE-942" }) {
		t.Fatalf("missing native API findings: %+v", findings)
	}
}

func TestAPIChecksDispatcherAndScopeGatesStopUnsafeOperations(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	approved, err := assessment.ParseApprovedOrigin("app", server.URL+"/api")
	if err != nil {
		t.Fatal(err)
	}
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{approved}, assessment.Exclusion{Method: "GET", PathPattern: "/api/private*"})
	base := APIEndpoint{Method: http.MethodGet, Path: "/private/items", Origin: server.URL, Source: "openapi", Resolved: true, Eligible: true}
	unsafe := APIEndpoint{Method: http.MethodPost, Path: "/write", Origin: server.URL, Source: "openapi", Resolved: true, Eligible: false, Reason: "state-changing method"}
	req := Request{Target: server.URL + "/api/", ScanDir: t.TempDir(), TypedAssessment: true, AppScope: &scope,
		EndpointTargets: []string{server.URL + "/api/private/items"}, APIEndpoints: []APIEndpoint{base, unsafe}}
	run := (apiChecksRunner{}).Run(context.Background(), req, Config{}, nil)
	if run.Status != "skipped" || requests != 0 || len(run.APIEndpointResults) != 2 || run.APIEndpointResults[0].Status != "skipped" || run.APIEndpointResults[1].Status != "skipped" {
		t.Fatalf("unsafe/excluded operations reached target: run=%+v requests=%d", run, requests)
	}
}

func TestAPIChecksRunnerRegisteredForWebAPIPlan(t *testing.T) {
	plan := PlanAssessment(PlanInput{Config: assessment.AssessmentConfig{Mode: assessment.ModeBlackBox,
		Types: []assessment.Type{assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://api.example.test/"}}}})
	for _, job := range plan.Jobs {
		if job.Scanner == "apichecks" {
			if job.State != PlanSelected || job.Stage != StageValidation || !HasAssessmentRunner("apichecks") || !slices.Contains(job.Dependencies, "katana:app:katana") {
				t.Fatalf("native API check job is not stage/dependency gated: %+v", job)
			}
			return
		}
	}
	t.Fatalf("API plan has no native API check job: %+v", plan.Jobs)
}

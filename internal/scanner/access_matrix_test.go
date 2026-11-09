package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// accessFixture serves one route per verdict the matrix must tell apart.
func accessFixture(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var log []string
	long := strings.Repeat("row ", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := map[string]string{"Bearer admin-token": "admin", "Bearer user-token": "user"}[r.Header.Get("Authorization")]
		mu.Lock()
		log = append(log, r.Method+" "+r.URL.Path+" as "+who)
		mu.Unlock()
		switch r.URL.Path {
		case "/app/admin/users": // the defect: no role check, only authentication
			if who == "" {
				http.Error(w, "login required", 401)
				return
			}
			_, _ = w.Write([]byte(`<html><input name="csrf_token" value="` + who + `-` + r.RemoteAddr + `">All users: ` + long + `</html>`))
		case "/app/admin/settings":
			if who != "admin" {
				http.Error(w, "forbidden", map[bool]int{true: 401, false: 403}[who == ""])
				return
			}
			_, _ = w.Write([]byte("settings " + long))
		case "/app/dashboard":
			if who == "" {
				http.Redirect(w, r, "/login", 302)
				return
			}
			_, _ = w.Write([]byte("dashboard for everyone " + long))
		case "/app/public":
			_, _ = w.Write([]byte("public page " + long))
		case "/app/profile":
			if who == "" {
				http.Error(w, "login required", 401)
				return
			}
			_, _ = w.Write([]byte("profile of " + who + " " + long))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &log
}

func accessMatrixRequest(t *testing.T, server *httptest.Server, userRefresh func(context.Context, []string) ([]string, error)) Request {
	t.Helper()
	origin, _ := assessment.ParseApprovedOrigin("app", server.URL+"/app")
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	surface := &AttackSurface{Scope: "app:app", Target: server.URL + "/app"}
	primary := inventoryID(surface.Scope, "target-bound")
	user := AuthenticationContextID("app", "user")
	add := func(path, owner string) {
		surface.Endpoints = append(surface.Endpoints, AttackSurfaceEndpoint{ID: inventoryID(path, owner), URL: server.URL + path, Method: "GET", ObservationKind: "observed", ObservedWithAuth: true, AuthContextID: owner, Kind: "page"})
	}
	add("/app/admin/users", primary)
	add("/app/admin/settings", primary)
	add("/app/dashboard", primary)
	add("/app/dashboard", user) // the user's own browsing also reached it
	add("/app/public", primary)
	add("/app/profile", primary)
	add("/app/logout", primary)
	same := func(_ context.Context, headers []string) ([]string, error) { return headers, nil }
	if userRefresh == nil {
		userRefresh = same
	}
	req := Request{Target: server.URL + "/app", TargetID: "app", TypedAssessment: true, AppScope: &scope, ScanDir: t.TempDir(), Inventory: surface, AttemptID: "matrix",
		AuthContexts: []AuthContext{
			{ID: AuthenticationContextID("app", "admin"), TargetID: "app", Identity: "admin", Role: "administrator", Primary: true, State: assessment.StateVerified, Headers: []string{"Authorization: Bearer admin-token"}, Refresh: same},
			{ID: user, TargetID: "app", Identity: "user", Role: "member", State: assessment.StateVerified, Headers: []string{"Authorization: Bearer user-token"}, Refresh: userRefresh},
		}}
	for _, endpoint := range surface.Endpoints {
		eligible, reason := accessMatrixEligible(endpoint)
		req.InputRequests = append(req.InputRequests, ScannerRequestInput{EndpointID: endpoint.ID, URL: endpoint.URL, Method: endpoint.Method, AuthContextID: endpoint.AuthContextID, Selected: eligible, Reason: reason})
	}
	return req
}

func TestAccessMatrixReportsOnlyValidatedBypass(t *testing.T) {
	server, log := accessFixture(t)
	req := accessMatrixRequest(t, server, nil)
	run := accessMatrixRunner{}.Run(context.Background(), req, Config{}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%s reason=%s", run.Status, run.Reason)
	}
	verdicts := map[string]string{}
	for _, result := range run.AccessMatrix {
		path := strings.TrimPrefix(result.URL, server.URL)
		verdicts[path+" as "+result.Identity] = result.Verdict
	}
	want := map[string]string{
		"/app/admin/users as user":      AccessBypassSuspected,
		"/app/admin/users as anonymous": AccessDenied,
		"/app/admin/settings as user":   AccessEnforced,
		"/app/dashboard as user":        AccessShared,
		"/app/dashboard as anonymous":   AccessDenied,
		"/app/public as user":           AccessPublic,
		"/app/public as anonymous":      AccessPublic,
		"/app/profile as user":          AccessDifferentResponse,
		"/app/dashboard as admin":       AccessShared, // the user's observation replayed as admin, also reached by admin
	}
	for key, expected := range want {
		if verdicts[key] != expected {
			t.Errorf("%s: got %q want %q", key, verdicts[key], expected)
		}
	}
	for _, line := range *log {
		if strings.Contains(line, "/app/logout") {
			t.Fatal("a route whose name suggests a state change was replayed")
		}
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.HasSuffix(findings[0].Endpoint, "/app/admin/users") || findings[0].Confidence != "tentative" || findings[0].CWE != "CWE-285" || !strings.Contains(findings[0].Evidence, "Anonymous: HTTP 401") {
		t.Fatalf("exactly one validated, tentative finding expected: %+v", findings)
	}
	artifact, _ := os.ReadFile(run.ArtifactPath)
	matrix, _ := os.ReadFile(run.AccessMatrix[0].EvidenceRef)
	if strings.Contains(string(artifact)+string(matrix), "admin-token") || strings.Contains(string(artifact)+string(matrix), "user-token") {
		t.Fatal("identity credentials leaked into saved evidence")
	}
	events, err := ReadCoverageEvents(run.CoverageEventsPath)
	if err != nil || len(events) == 0 {
		t.Fatalf("matrix requests must be recorded as coverage events: %v", err)
	}
}

func TestAccessMatrixWithholdsFindingsWhenASessionIsLost(t *testing.T) {
	server, _ := accessFixture(t)
	calls := 0
	req := accessMatrixRequest(t, server, func(_ context.Context, headers []string) ([]string, error) {
		calls++
		if calls > 1 { // renewed before the matrix, expired when re-verified after it
			return nil, errors.New("expired")
		}
		return headers, nil
	})
	run := accessMatrixRunner{}.Run(context.Background(), req, Config{}, nil)
	findings, _ := ParseRun(run)
	if len(findings) != 0 || run.Completeness != "partial" {
		t.Fatalf("an unverified session must not yield findings: findings=%+v completeness=%s", findings, run.Completeness)
	}
	for _, result := range run.AccessMatrix {
		if result.Identity == "user" && result.Verdict != AccessUnknown {
			t.Fatalf("rows for the lost identity must be unknown: %+v", result)
		}
	}
}

func TestAccessMatrixNeedsTwoIdentitiesAndIsSelectedForThem(t *testing.T) {
	server, _ := accessFixture(t)
	req := accessMatrixRequest(t, server, nil)
	req.AuthContexts = req.AuthContexts[:1]
	if run := (accessMatrixRunner{}).Run(context.Background(), req, Config{}, nil); run.Status != "not_applicable" {
		t.Fatalf("one identity cannot be compared: %s %s", run.Status, run.Reason)
	}
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, WorkflowVersion: "unified-v1", Types: []assessment.Type{assessment.TypeWebApplication},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}},
		Access:  []assessment.AccessBinding{{Kind: assessment.AccessBearerToken, Identity: "admin", Role: "administrator", CredentialID: "c1", TargetIDs: []string{"app"}}}}
	stateOf := func(cfg assessment.AssessmentConfig) PlanState {
		for _, decision := range PlanAssessment(PlanInput{Config: cfg}).Decisions {
			if decision.Scanner == "authz-matrix" && decision.TargetID == "app" {
				return decision.State
			}
		}
		return ""
	}
	if state := stateOf(cfg); state != PlanOptional {
		t.Fatalf("one identity leaves the matrix optional, got %q", state)
	}
	cfg.Access = append(cfg.Access, assessment.AccessBinding{Kind: assessment.AccessBearerToken, Identity: "member", Role: "member", CredentialID: "c2", TargetIDs: []string{"app"}})
	if state := stateOf(cfg); state != PlanSelected {
		t.Fatalf("two identities must select the matrix, got %q", state)
	}
	if identityRoutedScanner("authz-matrix") || !HasAssessmentRunner("authz-matrix") {
		t.Fatal("the matrix compares identities itself and must not be split into per-identity jobs")
	}
}

package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// TestSchemathesisRuntimeStaysInsideTheGatewayPolicy runs the pinned
// Schemathesis binary through a real recording gateway against a local HTTPS
// API. It proves on the wire what the unit tests prove on argv: only GET/HEAD
// reach the target, nothing reaches the excluded path or outside the
// application URL, every request carries the session the gateway injected,
// the session never appears on argv or in the saved artifact, and the target's
// own 500 becomes a finding.
func TestSchemathesisRuntimeStaysInsideTheGatewayPolicy(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_SCHEMATHESIS") != "1" {
		t.Skip("requires the pinned native Schemathesis runtime")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	const session = "Bearer runtime-session-7f3a"
	var mu sync.Mutex
	var seen []string
	unauthenticated := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.EscapedPath())
		if r.Header.Get("Authorization") != session {
			unauthenticated++
		}
		mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/app")
		switch {
		case strings.HasPrefix(path, "/items/"):
			id := strings.TrimPrefix(path, "/items/")
			if strings.Trim(id, "0123456789") != "" || id == "" {
				// The defect under test: unvalidated input reaches code that panics.
				http.Error(w, "unhandled conversion error", 500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":1}`))
		case path == "/search":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	origin, _ := assessment.ParseApprovedOrigin("app", server.URL+"/app")
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, assessment.Exclusion{PathPattern: "/app/private"})
	req := Request{
		WorkflowVersion: "unified-v1", Target: server.URL + "/app", TypedAssessment: true, StructuredDispatch: true,
		AppScope: &scope, ScanDir: t.TempDir(), AttemptID: "native-schemathesis", TargetAuth: "Authorization: " + session,
		APIEndpoints: []APIEndpoint{
			{Method: "GET", Path: "/items/{id}", OperationID: "getItem", Source: "openapi", Parameters: []APIParameter{{Name: "id", Location: "path", Required: true, SchemaType: "string"}}},
			{Method: "GET", Path: "/search", OperationID: "search", Source: "openapi", Parameters: []APIParameter{{Name: "q", Location: "query", Required: true, SchemaType: "string"}}},
			{Method: "GET", Path: "/private/{id}", OperationID: "private", Source: "openapi"},
			{Method: "DELETE", Path: "/items/{id}", OperationID: "deleteItem", Source: "openapi"},
		},
	}
	cfg := Config{SchemathesisPath: "schemathesis", SchemathesisTimeout: 3 * time.Minute, RateRPS: 50, WebMaxEndpoints: 1000, MaxOutputBytes: 32 << 20, Budget: NewAssessmentBudget(50, 1000, 3*time.Minute)}
	gateway, err := NewRecordingGateway(t.Context(), req, cfg, "schemathesis")
	if err != nil {
		t.Fatal(err)
	}
	gateway.client = server.Client()
	req.GatewayURL, req.GatewayCAPath, req.Gateway = gateway.URL, gateway.CAPath, gateway
	req.Secrets = append(req.Secrets, gateway.password)
	spec := buildSchemathesis(req, cfg)
	if spec.notApp != "" {
		t.Fatal(spec.notApp)
	}
	run := executeSpec(t.Context(), "schemathesis", req, cfg, spec, nil)
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	gateway.ApplyOutcome(&run)
	if run.Status != "completed" {
		t.Fatalf("status=%s outcome=%s reason=%s stdout=%s stderr=%s", run.Status, run.Outcome, run.Reason, readCapped(run.StdoutPath, 8000), readCapped(run.StderrPath, 8000))
	}

	mu.Lock()
	requests := append([]string(nil), seen...)
	missingSession := unauthenticated
	mu.Unlock()
	if len(requests) == 0 {
		t.Fatal("Schemathesis sent no request to the target")
	}
	for _, request := range requests {
		method, path, _ := strings.Cut(request, " ")
		if method != "GET" && method != "HEAD" {
			t.Errorf("non-read-only method reached the target: %s", request)
		}
		if !strings.HasPrefix(path, "/app") || strings.HasPrefix(path, "/app/private") {
			t.Errorf("request outside the approved boundary reached the target: %s", request)
		}
	}
	if missingSession != 0 {
		t.Errorf("%d target requests lacked the gateway-injected session", missingSession)
	}
	for _, arg := range spec.args {
		if strings.Contains(arg, "runtime-session-7f3a") {
			t.Fatal("the session was placed on the Schemathesis command line")
		}
	}
	if artifact, _ := os.ReadFile(run.ArtifactPath); strings.Contains(string(artifact), "runtime-session-7f3a") || strings.Contains(string(artifact), gateway.password) {
		t.Fatal("the saved event log contains the session or the gateway credential")
	}

	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	server500 := false
	for _, finding := range findings {
		if finding.RuleID == "ST101" && strings.Contains(finding.SourceID, "/items/{id}") && strings.Contains(finding.Evidence, "HTTP 500") {
			server500 = true
		}
	}
	if !server500 {
		t.Fatalf("the target's own 500 was not reported: %+v", findings)
	}
	events, err := ReadCoverageEvents(gateway.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	for _, event := range events {
		if event.Kind == "observed" {
			observed++
		}
	}
	if observed != len(requests) {
		t.Errorf("gateway recorded %d observed responses for %d target requests", observed, len(requests))
	}
	if run.Completeness != "partial" || run.Outcome != "PARTIAL" {
		t.Errorf("skipped operations must leave the run partial: completeness=%s outcome=%s limitations=%+v", run.Completeness, run.Outcome, run.Limitations)
	}
	t.Logf("native Schemathesis: %d target requests (GET/HEAD only), %d findings, limitations=%+v", len(requests), len(findings), run.Limitations)
}

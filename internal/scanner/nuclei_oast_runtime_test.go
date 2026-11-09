package scanner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// TestNucleiOASTRuntimeMatchesCallbackOnSelfHostedServer runs the retained
// Nuclei binary through the recording gateway with one signed OAST template
// against a disposable self-hosted Interactsh server
// (XALGORIX_TEST_INTERACTSH_SERVER). The local target plays a vulnerable
// application that fetches the injected callback host; the run must match the
// interaction, and the gateway must only ever see target traffic.
func TestNucleiOASTRuntimeMatchesCallbackOnSelfHostedServer(t *testing.T) {
	server := os.Getenv("XALGORIX_TEST_INTERACTSH_SERVER")
	if os.Getenv("XALGORIX_TEST_NUCLEI_OAST") != "1" || server == "" {
		t.Skip("requires retained Nuclei and a disposable self-hosted Interactsh server")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	var mu sync.Mutex
	var callbacks []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host := r.Header.Get("X-Callback"); host != "" {
			// Resolve the callback name to the Interactsh server, as public DNS
			// delegation would, and fetch it like an SSRF-prone application.
			request, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(server, "/")+"/", nil)
			request.Host = host
			if response, err := http.DefaultClient.Do(request); err == nil {
				response.Body.Close()
				mu.Lock()
				callbacks = append(callbacks, host)
				mu.Unlock()
			}
		}
		_, _ = w.Write([]byte("<html>fixture</html>"))
	}))
	defer target.Close()

	root := t.TempDir()
	templates := filepath.Join(root, "templates")
	if err := os.MkdirAll(templates, 0o700); err != nil {
		t.Fatal(err)
	}
	template := `id: xalgorix-oast-fixture
info:
  name: Local out-of-band fixture
  author: xalgorix
  severity: high
  tags: oast
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-Callback: {{interactsh-url}}
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
`
	if err := os.WriteFile(filepath.Join(templates, "receipt.yaml"), []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}
	signNativeFixtureTemplate(t, templates)
	// signNativeFixtureTemplate writes the fixture under receipt.yaml.

	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	req := Request{WorkflowVersion: "unified-v1", Target: target.URL + "/", StructuredDispatch: true, TypedAssessment: true, AppScope: &scope, ScanDir: root, AttemptID: "native-oast",
		EndpointTargets: []string{target.URL + "/"}, OASTServer: server, OASTToken: os.Getenv("XALGORIX_TEST_INTERACTSH_TOKEN")}
	req.InputRequests = []ScannerRequestInput{{EndpointID: "root", URL: target.URL + "/", Method: "GET", Selected: true}}
	if req.OASTToken != "" {
		req.Secrets = append(req.Secrets, req.OASTToken)
	}
	cfg := Config{NucleiPath: "nuclei", NucleiTemplatesDir: templates, NucleiTimeout: 3 * time.Minute, RateRPS: 10, WebMaxEndpoints: 100, MaxOutputBytes: 8 << 20, Budget: NewAssessmentBudget(10, 100, 3*time.Minute)}
	gateway, err := NewRecordingGateway(t.Context(), req, cfg, NucleiOASTVariant)
	if err != nil {
		t.Fatal(err)
	}
	req.GatewayURL, req.GatewayCAPath, req.Gateway = gateway.URL, gateway.CAPath, gateway
	req.Secrets = append(req.Secrets, gateway.password)
	spec := buildNuclei(req, cfg)
	if spec.notApp != "" {
		t.Fatal(spec.notApp)
	}
	run := executeSpec(t.Context(), "nuclei", req, cfg, spec, nil)
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ := ReadCoverageEvents(gateway.EventPath)
	var blocked []string
	for _, event := range events {
		if event.Kind == "blocked" {
			blocked = append(blocked, event.Method+" "+event.URL+" ("+event.Reason+")")
		}
	}
	findings, parseErr := ParseRun(run)
	mu.Lock()
	seen := len(callbacks)
	mu.Unlock()
	t.Logf("status=%s reason=%s callbacks=%d findings=%d blocked=%v", run.Status, run.Reason, seen, len(findings), blocked)
	for _, event := range events {
		t.Logf("gateway event: %s %s %s %d %s", event.Kind, event.Method, event.URL, event.ResponseCode, event.Reason)
	}
	t.Logf("args: %s", strings.Join(spec.args, " "))
	if run.Status != "completed" {
		t.Fatalf("stdout=%s stderr=%s", readCapped(run.StdoutPath, 6000), readCapped(run.StderrPath, 6000))
	}
	if seen == 0 {
		t.Fatalf("the target never received an interactsh payload\nargs=%v\nstdout=%s\nstderr=%s", spec.args, readCapped(run.StdoutPath, 6000), readCapped(run.StderrPath, 6000))
	}
	if len(blocked) != 0 {
		t.Fatalf("the gateway blocked traffic during the OAST run: %v", blocked)
	}
	if parseErr != nil || len(findings) != 1 || findings[0].RuleID != "xalgorix-oast-fixture" {
		t.Fatalf("the callback was not matched: %v %+v\nstderr=%s", parseErr, findings, readCapped(run.StderrPath, 6000))
	}
	if token := req.OASTToken; token != "" {
		for _, path := range []string{run.StdoutPath, run.StderrPath, run.ArtifactPath} {
			if data, _ := os.ReadFile(path); strings.Contains(string(data), token) {
				t.Fatalf("the Interactsh token leaked into %s", path)
			}
		}
	}
	t.Logf("matched %s", findings[0].Endpoint)
}

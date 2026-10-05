package scanner

import (
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestZAPRuntimeGatewayOriginsAndHEAD(t *testing.T) {
	zapURL := os.Getenv("XALGORIX_TEST_ZAP")
	if zapURL == "" {
		t.Skip("isolated native ZAP fixture opt-in")
	}
	host := os.Getenv("XALGORIX_SCANNER_GATEWAY_HOST")
	if host == "" {
		t.Fatal("fixture worker hostname required")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	var mu sync.Mutex
	seen := map[string]bool{}
	makeFixture := func() (*httptest.Server, string) {
		fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen[r.Method+" "+r.URL.RequestURI()] = true
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>fixture</body></html>")
		}))
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		fixture.Listener = l
		fixture.Start()
		t.Cleanup(fixture.Close)
		_, port, _ := net.SplitHostPort(l.Addr().String())
		return fixture, "http://" + net.JoinHostPort(host, port)
	}
	_, first := makeFixture()
	_, second := makeFixture()
	a, _ := assessment.ParseApprovedOrigin("app", first)
	a.PathPrefix = "/"
	b, _ := assessment.ParseApprovedOrigin("app", second)
	b.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{a, b})
	cfg := Config{ZAPURL: zapURL, ZAPAPIKey: "workflow-fixture", ZAPDedicated: true, ZAPTimeout: 90 * time.Second, WebMaxEndpoints: 10, MaxOutputBytes: 1 << 20}
	// This fixture validates routing and seeding; no vulnerability checks are claimed.
	if err := zapPost(cfg, "/JSON/ascan/action/disableAllScanners/", url.Values{}); err != nil {
		t.Fatal(err)
	}
	req := Request{Target: first + "/", AppScope: &scope, TypedAssessment: true, StructuredDispatch: true, Scope: "app:fixture", ScanDir: t.TempDir(), AttemptID: "native-fixture", InputRequests: []ScannerRequestInput{{EndpointID: "get", URL: first + "/same?x=1&x=2", Method: "GET", Selected: true}, {EndpointID: "head", URL: first + "/same?x=1&x=2", Method: "HEAD", Selected: true}, {EndpointID: "other", URL: second + "/", Method: "GET", Selected: true}}}
	graphql, err := ParseAPIDefinition([]byte(`type Query { ping: String hidden(id: ID!): String } type Mutation { erase: Boolean }`), first+"/graphql")
	if err != nil {
		t.Fatal(err)
	}
	req.APIEndpoints = append(graphql, APIEndpoint{Source: "openapi", Method: "GET", Path: "/api/ping", Origin: first, RequestURL: first + "/api/ping", Resolved: true, Eligible: true})
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("run: %+v", run)
	}
	if len(run.DefinitionImports) != 2 {
		t.Fatalf("missing schema imports: %+v", run.DefinitionImports)
	}
	for _, result := range run.DefinitionImports {
		if result.Status != "imported" {
			t.Fatalf("import failed: %+v", result)
		}
	}
	if len(run.Submissions) != 3 || len(run.NativeScanIDs) != 2 {
		t.Fatalf("missing submissions/scans: %+v", run)
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen["HEAD /same?x=1&x=2"] || !seen["GET /same?x=1&x=2"] {
		t.Fatalf("method semantics lost: %v", seen)
	}
	data, err := os.ReadFile(run.CoverageEventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"phase":"seeding"`) || !strings.Contains(string(data), `"kind":"observed"`) {
		t.Fatalf("no observed seed evidence: %s", data)
	}
	state, err := zapPostResponse(t.Context(), cfg, "/JSON/network/view/isHttpProxyEnabled/", url.Values{})
	if err != nil || valueString(state, "isHttpProxyEnabled") != "false" {
		t.Fatalf("proxy not restored: %v %v", state, err)
	}
}

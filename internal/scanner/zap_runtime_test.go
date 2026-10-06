package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"io"
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
	makeFixture := func(secure bool) (*httptest.Server, string) {
		fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			key := r.Method + " " + r.URL.RequestURI()
			if r.Method == "POST" {
				body, _ := io.ReadAll(r.Body)
				key += " " + string(body)
			}
			seen[key] = true
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>fixture</body></html>")
		}))
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		fixture.Listener = l
		scheme := "http"
		if secure {
			fixture.StartTLS()
			scheme = "https"
			transport := http.DefaultTransport.(*http.Transport).Clone()
			roots := x509.NewCertPool()
			roots.AddCert(fixture.Certificate())
			transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "example.com"}
			prior := http.DefaultTransport
			http.DefaultTransport = transport
			t.Cleanup(func() { transport.CloseIdleConnections(); http.DefaultTransport = prior })
		} else {
			fixture.Start()
		}
		t.Cleanup(fixture.Close)
		_, port, _ := net.SplitHostPort(l.Addr().String())
		return fixture, scheme + "://" + net.JoinHostPort(host, port)
	}
	_, first := makeFixture(false)
	_, second := makeFixture(true)
	a, _ := assessment.ParseApprovedOrigin("app", first)
	a.PathPrefix = "/"
	b, _ := assessment.ParseApprovedOrigin("app", second)
	b.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{a, b})
	cfg := Config{ZAPURL: zapURL, ZAPAPIKey: "workflow-fixture", ZAPDedicated: true, ZAPTimeout: 90 * time.Second, WebMaxEndpoints: 700, MaxOutputBytes: 4 << 20}
	// This fixture validates routing and seeding; no vulnerability checks are claimed.
	if err := zapPost(cfg, "/JSON/ascan/action/disableAllScanners/", url.Values{}); err != nil {
		t.Fatal(err)
	}
	req := Request{WorkflowVersion: "unified-v1", Target: first + "/", AppScope: &scope, TypedAssessment: true, StructuredDispatch: true, Scope: "app:fixture", ScanDir: t.TempDir(), AttemptID: "native-fixture", InputRequests: []ScannerRequestInput{{EndpointID: "get", URL: first + "/same?x=1&x=2", Method: "GET", Selected: true}, {EndpointID: "head", URL: first + "/same?x=1&x=2", Method: "HEAD", Selected: true}, {EndpointID: "other", URL: second + "/", Method: "GET", Selected: true}}}
	graphql, err := ParseAPIDefinition([]byte(`type Query { ping: String hidden(id: ID!): String } type Mutation { erase: Boolean }`), first+"/graphql")
	if err != nil {
		t.Fatal(err)
	}
	req.APIEndpoints = append(graphql, APIEndpoint{Source: "openapi", Method: "GET", Path: "/api/ping", Origin: first, RequestURL: first + "/api/ping", Resolved: true, Eligible: true})
	for i, endpoint := range req.APIEndpoints {
		if endpoint.Eligible && endpoint.Resolved {
			req.InputRequests = append(req.InputRequests, ScannerRequestInput{EndpointID: fmt.Sprintf("api-%d", i), URL: endpoint.RequestURL, Method: endpoint.Method, Selected: true})
		}
	}
	body := `{"query":"query {ping}"}`
	req.InputRequests = append(req.InputRequests, ScannerRequestInput{EndpointID: "post-read", URL: second + "/graphql", Method: "POST", ContentType: "application/json", Body: body, BodyDigest: bodyDigest(body), ReadOnly: true, Selected: true, Headers: map[string]string{"X-Fixture": "exact-request"}})
	// The acceptance inventory contains 684 exact request variants, including
	// repeated query values, HEAD and a captured read-only HTTPS POST.
	for len(req.InputRequests) < 684 {
		i := len(req.InputRequests)
		req.InputRequests = append(req.InputRequests, ScannerRequestInput{EndpointID: fmt.Sprintf("bulk-%d", i), URL: fmt.Sprintf("%s/api/%d?x=1&x=2", first, i), Method: "GET", Selected: true})
	}
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
	if len(run.Submissions) != len(req.InputRequests) || len(run.NativeScanIDs) != 2 {
		t.Fatalf("missing submissions/scans: %+v", run)
	}
	for _, submission := range run.Submissions {
		if submission.Status != "acknowledged" {
			t.Fatalf("native input was not acknowledged: %+v", submission)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen["POST /graphql "+body] || !seen["HEAD /same?x=1&x=2"] || !seen["GET /same?x=1&x=2"] {
		t.Fatalf("method semantics lost: %v", seen)
	}
	data, err := os.ReadFile(run.CoverageEventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"phase":"seeding"`) || !strings.Contains(string(data), `"kind":"observed"`) {
		t.Fatalf("no observed seed evidence: %s", data)
	}
	observed := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		var event CoverageEvent
		if json.Unmarshal([]byte(line), &event) == nil && event.Kind == "observed" && event.Phase == "seeding" {
			for _, id := range event.EndpointIDs {
				observed[id] = true
			}
		}
	}
	if len(observed) != 684 {
		t.Fatalf("only %d of 684 native seeds have HTTP evidence", len(observed))
	}
	for _, input := range req.InputRequests {
		if !observed[input.EndpointID] {
			t.Fatalf("native request %s has no saved receipt", input.EndpointID)
		}
	}
	state, err := zapPostResponse(t.Context(), cfg, "/JSON/network/view/isHttpProxyEnabled/", url.Values{})
	if err != nil || valueString(state, "isHttpProxyEnabled") != "false" {
		t.Fatalf("proxy not restored: %v %v", state, err)
	}
}

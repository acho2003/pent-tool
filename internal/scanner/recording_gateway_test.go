package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestGatewayRecordsRequestsAndBlocksScopeWritesAndCredentialLeak(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Cookie") != "session=verified" {
			t.Error("credential missing")
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	req := Request{Target: target.URL, AppScope: &scope, ScanDir: t.TempDir(), TargetAuth: "Cookie: session=verified", AttemptID: "attempt"}
	g, err := NewRecordingGateway(context.Background(), req, Config{}, "wapiti")
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse(g.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	for _, tc := range []struct {
		method, raw string
		status      int
	}{{"GET", target.URL + "/?token=secret", 200}, {"POST", target.URL + "/write", 403}, {"GET", "http://outside.test/", 403}} {
		request, _ := http.NewRequest(tc.method, tc.raw, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatal(response.StatusCode)
		}
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(g.EventPath)
	if hits != 1 || strings.Contains(string(data), "token=secret") || strings.Contains(string(data), "session=verified") || !strings.Contains(string(data), `"kind":"observed"`) {
		t.Fatalf("hits=%d events=%s", hits, data)
	}
}
func TestGatewayInspectsTLSRequests(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secure")) }))
	defer target.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	g, err := NewRecordingGateway(t.Context(), Request{Target: target.URL, AppScope: &scope, ScanDir: t.TempDir()}, Config{}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.client = target.Client()
	roots := x509.NewCertPool()
	ca, _ := os.ReadFile(g.CAPath)
	roots.AppendCertsFromPEM(ca)
	proxy, _ := url.Parse(g.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	response, err := client.Get(target.URL + "/api")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "secure" {
		t.Fatal(string(body))
	}
}

func TestOutputLimitKeepsCompleteJSONRecords(t *testing.T) {
	path := t.TempDir() + "/zap.json"
	os.WriteFile(path, []byte(`{"alerts":[{"url":"https://app.test/a","evidence":"long evidence long evidence"},{"url":"https://app.test/b","evidence":"long evidence long evidence"}]}`), 0600)
	if bounded, err := boundWebArtifact(path, "zap", 110); !bounded || err != nil {
		t.Fatal("limit not recorded")
	}
	data, _ := os.ReadFile(path)
	var value any
	if json.Unmarshal(data, &value) != nil || len(data) > 110 {
		t.Fatalf("invalid bounded report %s", data)
	}
}

func TestGatewayBindsHostToApprovedURL(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "forged.test" {
			t.Error("forged authority forwarded")
		}
		w.Write([]byte("ok"))
	}))
	defer fixture.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", fixture.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	g, err := NewRecordingGateway(t.Context(), Request{Target: fixture.URL, ScanDir: t.TempDir(), AppScope: &scope}, Config{}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	request, _ := http.NewRequest("GET", fixture.URL, nil)
	request.Host = "forged.test"
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(g.username+":"+g.password)))
	response := httptest.NewRecorder()
	g.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
}

func TestGatewayAttributesOnlyTheExactBodyVariant(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer fixture.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", fixture.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))
	req := Request{Target: fixture.URL, ScanDir: t.TempDir(), AppScope: &scope, InputRequests: []ScannerRequestInput{{EndpointID: "first", URL: fixture.URL + "/", Method: "GET", BodyDigest: hex.EncodeToString(first[:]), Selected: true}, {EndpointID: "second", URL: fixture.URL + "/", Method: "GET", BodyDigest: hex.EncodeToString(second[:]), Selected: true}}}
	gateway, err := NewRecordingGateway(t.Context(), req, Config{}, "zap")
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse(gateway.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	request, _ := http.NewRequest("GET", fixture.URL, strings.NewReader("first"))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	gateway.Close()
	events, err := ReadCoverageEvents(gateway.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Kind == "observed" {
			found = true
			if len(event.EndpointIDs) != 1 || event.EndpointIDs[0] != "first" {
				t.Fatal("body variants conflated", event)
			}
		}
	}
	if !found {
		t.Fatal("missing observed request")
	}
}

func TestGatewayRestrictionsMakeSuccessfulScannerPartial(t *testing.T) {
	gateway := &RecordingGateway{}
	gateway.record(CoverageEvent{Kind: "blocked", Reason: "assessment budget exhausted"})
	gateway.record(CoverageEvent{Kind: "failed", Reason: "upstream response exceeds recording limit"})
	gateway.record(CoverageEvent{Kind: "blocked", Reason: "assessment budget exhausted"})
	run := Run{Status: "completed", Outcome: "SUCCESS_NO_FINDINGS", Completeness: "complete"}
	gateway.ApplyOutcome(&run)
	if run.Outcome != "PARTIAL" || run.Completeness != "partial" || len(run.Limitations) != 2 {
		t.Fatal("restrictions hidden", run)
	}
	failed := Run{Status: "failed", Outcome: "AUTH_FAILED"}
	gateway.ApplyOutcome(&failed)
	if failed.Outcome != "AUTH_FAILED" {
		t.Fatal("execution failure replaced", failed)
	}
}

func TestGatewayAllowsOnlyCapturedReadOnlyGraphQLBody(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte(`{"data":{"viewer":"ok"}}`)) }))
	defer target.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	body := `{"query":"query {viewer}"}`
	input := ScannerRequestInput{EndpointID: "read", URL: target.URL + "/graphql", Method: "POST", ContentType: "application/json", BodyDigest: bodyDigest(body), Body: body, Selected: true, ReadOnly: true}
	gateway, err := NewRecordingGateway(t.Context(), Request{Target: target.URL, AppScope: &scope, ScanDir: t.TempDir(), InputRequests: []ScannerRequestInput{input}}, Config{}, "zap")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	proxy, _ := url.Parse(gateway.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	for _, tc := range []struct {
		body   string
		status int
	}{{body, 200}, {`{"query":"mutation {deleteUser}"}`, 403}, {`{"query":"query {other}"}`, 403}, {"", 403}} {
		request, _ := http.NewRequest("POST", input.URL, strings.NewReader(tc.body))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s status %d", tc.body, response.StatusCode)
		}
	}
	if hits != 1 {
		t.Fatalf("unapproved POST reached target: %d", hits)
	}
}

func TestGatewayDoesNotAttributeAuthenticatedResponseToAnonymousVariant(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "session=verified" {
			t.Error("missing bound credential")
		}
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	contextID := inventoryID("app:app", "target-bound")
	req := Request{Target: target.URL, AppScope: &scope, ScanDir: t.TempDir(), TargetAuth: "Cookie: session=verified", InputRequests: []ScannerRequestInput{
		{EndpointID: "anonymous", InventoryScope: "app:app", URL: target.URL + "/", Method: "GET", Selected: true},
		{EndpointID: "authenticated", AuthContextID: contextID, InventoryScope: "app:app", URL: target.URL + "/", Method: "GET", Selected: true},
		{EndpointID: "different-role", AuthContextID: "another-role", InventoryScope: "app:app", URL: target.URL + "/", Method: "GET", Selected: true},
	}}
	g, err := NewRecordingGateway(t.Context(), req, Config{}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse(g.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := ReadCoverageEvents(g.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	observed := false
	for _, event := range events {
		if event.Kind == "observed" {
			observed = true
			if len(event.EndpointIDs) != 1 || event.EndpointIDs[0] != "authenticated" {
				t.Fatalf("wrong authentication attribution: %+v", event)
			}
		}
	}
	if !observed {
		t.Fatal("missing observed response")
	}
}

func TestInputManifestPreservesNonsecretAuthenticationContext(t *testing.T) {
	req := Request{ScanDir: t.TempDir(), InputRequests: []ScannerRequestInput{{EndpointID: "request", AuthContextID: "role-context-id", URL: "https://app.test/private", Method: "GET", Headers: map[string]string{"Cookie": "private-cookie-value"}, Selected: true}}}
	path, err := SaveScannerInputs(req, "zap")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"auth_context_id": "role-context-id"`) || strings.Contains(string(data), "private-cookie-value") {
		t.Fatalf("unsafe context manifest: %s", data)
	}
}

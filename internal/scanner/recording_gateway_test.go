package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	if !boundWebArtifact(path, "zap", 110) {
		t.Fatal("limit not recorded")
	}
	data, _ := os.ReadFile(path)
	var value any
	if json.Unmarshal(data, &value) != nil || len(data) > 110 {
		t.Fatalf("invalid bounded report %s", data)
	}
}

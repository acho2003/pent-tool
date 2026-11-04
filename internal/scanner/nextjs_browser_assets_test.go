package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func browserAssetKey(t *testing.T) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	payload, _ := json.Marshal(map[string]string{"key": encoded})
	return encoded, payload
}

func TestNextjsAuthenticatedAssetsStayWithinIdentityAndResponseBounds(t *testing.T) {
	key, payload := browserAssetKey(t)
	for _, tc := range []struct {
		name               string
		profile            string
		auth, same, access bool
		status             int
		path               string
		want               bool
	}{
		{"authenticated", ProfileNextjsDeep, true, true, false, 200, "/private.js", true},
		{"anonymous", ProfileNextjsDeep, false, true, false, 200, "/private.js", false},
		{"foreign", ProfileNextjsDeep, true, false, false, 200, "/private.js", false},
		{"ordinary", "", true, true, false, 200, "/private.js", false},
		{"denied", ProfileNextjsDeep, true, true, false, 403, "/private.js", false},
		{"access-check", ProfileNextjsDeep, true, true, true, 200, "/private.js", false},
		{"not-asset", ProfileNextjsDeep, true, true, false, 200, "/private.txt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Profile: tc.profile, BrowserAccessTest: tc.access}
			if tc.auth {
				req.TargetAuth = "Cookie: secret"
			}
			finding, err := nextjsAuthenticatedAsset(req, "https://app.test"+tc.path, tc.status, "text/plain", payload, tc.same, "evidence")
			if err != nil || (finding != nil) != tc.want {
				t.Fatalf("finding=%v err=%v", finding, err)
			}
			if finding != nil {
				raw, _ := json.Marshal(finding)
				if strings.Contains(string(raw), key) || strings.Contains(string(raw), "Cookie:") || finding.RuleID != "nextjs-authenticated-private-key" {
					t.Fatal("sensitive or incorrect finding")
				}
			}
		})
	}
	mapBody, _ := json.Marshal(map[string]any{"version": 3, "sources": []string{"private.ts"}, "sourcesContent": []string{string(payload)}, "mappings": "ACAA"})
	finding, err := nextjsAuthenticatedAsset(Request{Profile: ProfileNextjsDeep, TargetAuth: "Cookie: secret"}, "https://app.test/private.js.map", 200, "application/json", mapBody, true, "evidence")
	if finding == nil || err == nil {
		t.Fatal("malformed mapping should retain key evidence and report a gap")
	}
}

func TestBrowserRuntimeAuthenticatedAssetFindings(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("native Chromium fixture opt-in")
	}
	key, payload := browserAssetKey(t)
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "session=asset-fixture" {
			http.Error(w, "denied", 403)
			return
		}
		if r.URL.Path == "/private.js" {
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, "window.fixture=%s", payload)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="/private.js"></script></html>`)
	}))
	defer fixture.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", fixture.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	req := Request{Profile: ProfileNextjsDeep, Target: fixture.URL + "/", Scope: "app:fixture", ScanDir: t.TempDir(), AppScope: &scope, TargetAuth: "Cookie: session=asset-fixture", AuthRefresh: func(_ context.Context, h []string) ([]string, error) { return h, nil }}
	run := DiscoverBrowser(t.Context(), req, Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 20})
	if run.Status != "completed" || !run.Authenticated {
		t.Fatalf("browser failed: %+v", run)
	}
	findings, err := ParseRun(run)
	if err != nil || len(findings) != 1 || findings[0].Scanner != "browser" {
		t.Fatalf("authenticated finding missing: %v %v", findings, err)
	}
	raw, _ := os.ReadFile(run.ArtifactPath)
	if strings.Contains(string(raw), key) || strings.Contains(string(raw), "session=asset-fixture") || strings.Contains(string(raw), "BEGIN PRIVATE KEY") {
		t.Fatal("key or credentials persisted")
	}
	if err := VerifyChecksum(run); err != nil {
		t.Fatal(err)
	}
}

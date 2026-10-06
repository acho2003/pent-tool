package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestZAPRuntimeSupplementalDiscoveryIsReadOnlyAndFeedsInventory(t *testing.T) {
	service := os.Getenv("XALGORIX_TEST_ZAP")
	if service == "" {
		t.Skip("isolated native ZAP fixture opt-in")
	}
	host := os.Getenv("XALGORIX_SCANNER_GATEWAY_HOST")
	if host == "" {
		t.Fatal("fixture worker hostname required")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	var mu sync.Mutex
	seen := map[string]int{}
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.RequestURI()]++
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer supplemental-fixture" {
			t.Error("discovery credential missing")
		}
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/approved/" {
			fmt.Fprint(w, `<html><body><a href="/approved/new/?x=1&amp;x=2">new</a><a href="/approved/logout">excluded</a><a href="/outside">outside</a><form method="post" action="/approved/write"><input name="value" value="fixture"><input type="submit"></form></body></html>`)
		} else {
			fmt.Fprint(w, "<html>read fixture</html>")
		}
	}))
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.Listener = listener
	fixture.Start()
	defer fixture.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	target := "http://" + net.JoinHostPort(host, port) + "/approved/"
	origin, _ := assessment.ParseApprovedOrigin("app", target)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, assessment.Exclusion{Method: "*", PathPattern: "/approved/logout"})
	cfg := Config{ZAPURL: service, ZAPAPIKey: "workflow-fixture", ZAPDedicated: true, ZAPTimeout: 90 * time.Second, WebMaxEndpoints: 64, MaxOutputBytes: 1 << 20}
	req := Request{WorkflowVersion: "unified-v1", TypedAssessment: true, StructuredDispatch: true, ZAPDiscoveryOnly: true, Target: target, Scope: "discovery:app:zap", ReplayScope: "app:app", ScanDir: t.TempDir(), AppScope: &scope, AttemptID: "supplemental-native", PlanFingerprint: "sha256:supplemental-native", TargetAuth: "Authorization: Bearer supplemental-fixture", AuthRefresh: func(context.Context, []string) ([]string, error) {
		return []string{"Authorization: Bearer supplemental-fixture"}, nil
	}, InputRequests: []ScannerRequestInput{{EndpointID: "root", URL: target, Method: "GET", Selected: true, AuthContextID: inventoryID("app:app", "target-bound"), InventoryScope: "app:app"}}}
	prior, err := zapPostResponse(t.Context(), cfg, "/JSON/spider/view/optionProcessForm/", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	run := zapRunner{}.Run(t.Context(), req, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("native discovery failed: %+v", run)
	}
	after, err := zapPostResponse(t.Context(), cfg, "/JSON/spider/view/optionProcessForm/", url.Values{})
	if err != nil || valueString(prior, "ProcessForm") != valueString(after, "ProcessForm") {
		t.Fatalf("daemon policy not restored: %+v %v", after, err)
	}
	inventory, err := ParseKatanaAttackSurfaceScoped(run.ArtifactPath, "app:app", target, true, &scope)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, endpoint := range inventory.Endpoints {
		if strings.HasSuffix(endpoint.URL, "/approved/new/?x=1&x=2") && endpoint.StatusCode == 200 && endpoint.ObservationKind == "observed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("supplemental response missing from shared inventory: %+v", inventory.Endpoints)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["GET /approved/new/?x=1&x=2"] == 0 {
		t.Fatalf("new route not requested: %+v", seen)
	}
	for key := range seen {
		if strings.HasPrefix(key, "POST ") || strings.Contains(key, "/outside") || strings.Contains(key, "/approved/logout") {
			t.Fatalf("unsafe discovery escaped gateway: %+v", seen)
		}
	}
	events, err := ReadCoverageEvents(run.CoverageEventsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Phase == "active_test" {
			t.Fatalf("discovery ran active vulnerability testing: %+v", event)
		}
	}
}

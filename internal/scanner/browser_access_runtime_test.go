package scanner

import (
	"os"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/test/stagedlab"
)

// An application that answers an anonymous visitor to a protected page with
// HTTP 401 (rather than a login redirect) must still produce an evaluable
// negative control: the marker is simply absent. Opt-in: needs Chromium.
func TestBrowserRuntimeAnonymousControlOnUnauthorizedProtectedPage(t *testing.T) {
	chrome := os.Getenv("XALGORIX_TEST_CHROMIUM")
	if chrome == "" {
		t.Skip("requires Chromium")
	}
	lab := stagedlab.Start(t)
	origin, _ := assessment.ParseApprovedOrigin("app", lab.Primary.URL+stagedlab.PathPrefix)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	req := Request{Target: lab.Primary.URL + stagedlab.PathPrefix + "private", ScanDir: t.TempDir(), AppScope: &scope, BrowserAccessTest: true, BrowserCheckpointMarker: stagedlab.AdminMarker}
	run := DiscoverBrowser(t.Context(), req, Config{KatanaChromePath: chrome, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 40})
	t.Logf("anonymous run: status=%q auth=%q reason=%q outcome=%q", run.Status, run.AuthState, run.Reason, run.Outcome)
	if run.Status != "failed" || run.Reason != "browser protected-route marker was not confirmed" {
		t.Fatalf("anonymous negative control was not evaluable: status=%q reason=%q", run.Status, run.Reason)
	}
}

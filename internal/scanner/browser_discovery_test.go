package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestBrowserRequestBoundary(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", Port: 443, PathPrefix: "/"}}, assessment.Exclusion{Method: "GET", PathPattern: "/logout", Reason: "ends session"})
	req := Request{AppScope: &scope}
	for _, tc := range []struct {
		method, url string
		allowed     bool
	}{{"GET", "https://app.test/api", true}, {"GET", "https://alias.test/api", false}, {"POST", "https://app.test/form", false}, {"GET", "https://app.test/logout", false}, {"GET", "http://app.test/", false}} {
		if err := browserRequestAllowed(req, Config{}, tc.method, tc.url); (err == nil) != tc.allowed {
			t.Fatalf("%s %s: %v", tc.method, tc.url, err)
		}
	}
}

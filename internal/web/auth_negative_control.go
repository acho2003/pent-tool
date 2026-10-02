package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// authVerificationProvenance marks authenticated-web evidence that comes from
// an executed verification (positive check plus negative control) rather than
// from the mere presence of a credential reference.
const authVerificationProvenance = "verification_probe"

// formConfigError is a form-login problem detected before any request was
// sent (incomplete fields, an unsupported submit format, a login URL outside
// the application). It maps to StateUnavailable, not StateFailed, because no
// verification ran. Its text is a fixed, secret-free phrase.
type formConfigError string

func (e formConfigError) Error() string { return string(e) }

// verifyNegativeControl proves the verification marker depends on the
// credential: one GET with no credentials and a fresh cookie jar, following
// redirects only while they stay inside scope, must not show the marker. A
// marker visible anonymously means the positive check proved nothing, so the
// verification fails. It runs once per verification, never per refresh.
func verifyNegativeControl(ctx context.Context, scope assessment.AppScope, verifyURL, marker string) error {
	if marker == "" || len(marker) > 256 || strings.ContainsAny(marker, "\r\n\x00") {
		return fmt.Errorf("negative-control marker is missing or invalid")
	}
	if !scopeAllowsRequest(scope, verifyURL) {
		return fmt.Errorf("negative-control URL is outside the application scope")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("create isolated negative-control cookie jar")
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !scopeAllowsRequest(scope, req.URL.String()) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return fmt.Errorf("invalid negative-control request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("negative-control request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("negative-control response could not be read")
	}
	// The status does not matter: a marker in any anonymous response (even an
	// error page) cannot distinguish an authenticated session.
	if strings.Contains(string(body), marker) {
		return fmt.Errorf("verification marker is visible without credentials (HTTP %d at %s)", resp.StatusCode, resp.Request.URL.Path)
	}
	return nil
}

// applicationScope is the scope of one application URL, built by the shared
// assessment matcher so default ports, host case and dot segments compare the
// same way everywhere.
func applicationScope(appURL string) assessment.AppScope {
	return assessment.AppScopeForTarget(assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "application", Kind: assessment.KindURL, Value: appURL}}}, "application")
}

// scopeAllowsRequest reports whether a GET to candidate is inside scope and
// not excluded from testing.
func scopeAllowsRequest(scope assessment.AppScope, candidate string) bool {
	if ok, _ := scope.Allows(candidate); !ok {
		return false
	}
	excluded, _ := scope.Excluded(http.MethodGet, candidate)
	return !excluded
}

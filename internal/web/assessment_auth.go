package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// maxSessionRenewals bounds how many fresh form logins one target may get per
// scan. A multi-stage workflow can lose its session more than once; an
// application that keeps expiring it stops authenticated work instead of
// being logged into indefinitely.
const maxSessionRenewals = 3

// prepareAssessmentAuthentication verifies target-bound headers or a form
// session before any typed scanner receives them. Verification is a positive
// check with the credential plus one unauthenticated negative control; a saved
// credential or a successful response alone never makes a target verified.
// Configuration and vault problems are unavailable (nothing ran); a
// verification that ran and was rejected is failed. Secret values remain in
// runtime memory only.
func (s *Server) prepareSingleContextAuthentication(ctx context.Context, plan *scanner.AssessmentPlan) (map[string][]string, error) {
	headersByTarget := map[string][]string{}
	if plan == nil || len(plan.Config.Access) == 0 {
		return headersByTarget, nil
	}
	for i := range plan.Jobs {
		if plan.Jobs[i].Scanner == "zap" || plan.Jobs[i].Scanner == "nuclei" {
			plan.Jobs[i].ExecutionMode = "unauthenticated"
		}
	}
	for i := range plan.Decisions {
		if plan.Decisions[i].Scanner == "zap" || plan.Decisions[i].Scanner == "nuclei" {
			plan.Decisions[i].ExecutionMode = "unauthenticated"
		}
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		for _, binding := range plan.Config.Access {
			if !webAuthenticationKind(binding.Kind) {
				continue
			}
			for _, targetID := range binding.TargetIDs {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "credential vault is unavailable; authenticated scanning was skipped")
			}
		}
		for i := range plan.Jobs {
			if (plan.Jobs[i].Scanner == "zap" || plan.Jobs[i].Scanner == "nuclei") && hasBlockingAuth(plan.Capabilities, plan.Jobs[i].TargetID) {
				plan.Jobs[i].State = scanner.PlanSkipped
				plan.Jobs[i].Reason = "authenticated scan skipped because credential verification was unavailable"
			}
		}
		return headersByTarget, nil
	}
	// One login per token credential, shared by every target bound to it.
	tokenSessions := map[string]*tokenSession{}
	tokenFailures := map[string]error{}
	for _, binding := range plan.Config.Access {
		if !webAuthenticationKind(binding.Kind) {
			continue
		}
		if binding.Kind == assessment.AccessFormLogin && len(binding.TargetIDs) != 1 {
			for _, targetID := range binding.TargetIDs {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "form login requires one explicitly bound application target")
			}
			continue
		}
		targets := map[string]assessment.Target{}
		for _, target := range plan.Config.Targets {
			targets[target.ID] = target
		}
		for _, targetID := range binding.TargetIDs {
			target, ok := targets[targetID]
			if !ok {
				return nil, fmt.Errorf("authentication binding references unknown target")
			}
			record, getErr := vault.Get(binding.CredentialID, targetID)
			if getErr != nil || record.Kind != binding.Kind {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "bound credential could not be resolved")
				continue
			}
			scope := assessment.AppScopeForTarget(plan.Config, targetID)
			verifyURL := binding.VerifyURL
			if verifyURL == "" {
				verifyURL = target.Value
			}
			if !urlWithinApplication(target.Value, verifyURL) || !scopeAllowsRequest(scope, verifyURL) {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "verification URL is outside the application origin or path boundary")
				continue
			}
			formBrowserLogin := binding.Kind == assessment.AccessFormLogin && strings.EqualFold(strings.TrimSpace(record.Values["submit_format"]), "browser")
			if binding.Kind == assessment.AccessFormLogin && binding.VerifyMarker == "" && !formBrowserLogin {
				// Markerless verification is redirect-based and needs a real
				// browser. The HTTP form replayer cannot evaluate it, so a marker
				// stays required there.
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "form login without a verify_marker requires browser login (submit_format=browser); add a marker or switch the credential to browser login")
				continue
			}
			var lines []string
			unverifiedReason := ""
			if binding.Kind == assessment.AccessTokenLogin {
				session, failure := tokenSessions[binding.CredentialID], tokenFailures[binding.CredentialID]
				if session == nil && failure == nil {
					cfg, cfgErr := parseTokenLoginConfig(record.Values)
					if cfgErr == nil && !tokenLoginAllowed(cfg.loginURL, assessmentURLScopes(plan.Config)) {
						cfgErr = tokenConfigError("the login URL is outside every application target of this assessment")
					}
					if cfgErr != nil {
						failure = cfgErr
					} else {
						session, failure = newTokenSession(ctx, cfg)
					}
					tokenSessions[binding.CredentialID], tokenFailures[binding.CredentialID] = session, failure
				}
				if failure != nil {
					var configErr tokenConfigError
					if errors.As(failure, &configErr) {
						setAuthCapability(plan, targetID, assessment.StateUnavailable, "token login is not usable ("+configErr.Error()+"); authenticated scanning was skipped")
					} else {
						// obtainLoginToken errors are fixed, secret-free phrases.
						setAuthVerification(plan, targetID, assessment.StateFailed, "token login failed ("+failure.Error()+"); authenticated scanning was skipped")
					}
					continue
				}
				lines = []string{session.headerLine()}
				positive, verifyErr := probeHeaderSession(ctx, verifyURL, binding.VerifyMarker, lines, target.Value)
				if verifyErr == nil && binding.VerifyMarker != "" {
					negativeMarker := binding.NegativeMarker
					if negativeMarker == "" {
						negativeMarker = binding.VerifyMarker
					}
					verifyErr = verifyNegativeControl(ctx, scope, verifyURL, negativeMarker)
				} else if verifyErr == nil {
					verifyErr = verifyAnonymousContrast(ctx, scope, verifyURL, positive)
				}
				if verifyErr != nil {
					if binding.VerifyURL != "" || isProbeTransportError(verifyErr) {
						setAuthVerification(plan, targetID, assessment.StateFailed, "token verification failed ("+verifyErr.Error()+"); authenticated scanning was skipped")
						continue
					}
					// No protected path was supplied: the token is still applied,
					// but nothing claims this service accepted it.
					unverifiedReason = "token login succeeded and the token is applied, but access to this service was not verified (no protected path supplied and the anonymous response was not distinguishable)"
				}
			} else if binding.Kind == assessment.AccessFormLogin {
				browserLogin := formBrowserLogin
				var cookieHeader string
				if browserLogin {
					// NextAuth/SPA logins: drive a real browser instead of the HTTP
					// replayer. The captured session is a Cookie header.
					ch, _, captureErr := s.captureBrowserLoginSession(ctx, target.Value, verifyURL, binding.VerifyMarker, record.Values)
					if captureErr != nil {
						setAuthVerification(plan, targetID, assessment.StateFailed, "browser login failed ("+captureErr.Error()+"); authenticated scanning was skipped")
						continue
					}
					cookieHeader = ch
				} else {
					ch, loginErr := verifyFormSession(ctx, target.Value, verifyURL, binding.VerifyMarker, record.Values)
					var configErr formConfigError
					if errors.As(loginErr, &configErr) {
						setAuthCapability(plan, targetID, assessment.StateUnavailable, "form login is not usable ("+configErr.Error()+"); authenticated scanning was skipped")
						continue
					}
					if loginErr != nil {
						// verifyFormSession errors are fixed, secret-free phrases.
						setAuthVerification(plan, targetID, assessment.StateFailed, "form login or session verification failed ("+loginErr.Error()+"); authenticated scanning was skipped")
						continue
					}
					cookieHeader = ch
				}
				lines = []string{cookieHeader}
				if browserLogin {
					// A browser-login credential is a JS/SPA app: verify the captured
					// session in the browser (real render + anonymous negative
					// control). An HTTP marker check is unsound here — the marker is
					// JS-rendered, so it is never present in the anonymous raw HTML
					// and the negative control would pass without proving anything.
					if err := s.verifyBrowserCredential(ctx, target.Value, verifyURL, binding.VerifyMarker, lines, record.BrowserStorage, true); err != nil {
						setAuthVerification(plan, targetID, assessment.StateFailed, "browser protected-route verification failed ("+err.Error()+"); authenticated scanning was skipped")
						continue
					}
				} else {
					if record.BrowserStorage != nil || binding.VerifyBrowser {
						if err := s.verifyBrowserCredential(ctx, target.Value, verifyURL, binding.VerifyMarker, lines, record.BrowserStorage, true); err != nil {
							setAuthVerification(plan, targetID, assessment.StateFailed, "browser protected-route verification failed")
							continue
						}
					}
					negativeMarker := binding.NegativeMarker
					if negativeMarker == "" {
						negativeMarker = binding.VerifyMarker
					}
					if controlErr := verifyNegativeControl(ctx, scope, verifyURL, negativeMarker); controlErr != nil {
						setAuthVerification(plan, targetID, assessment.StateFailed, "negative control failed ("+controlErr.Error()+"); authenticated scanning was skipped")
						continue
					}
				}
			} else {
				var convErr error
				lines, convErr = credentialHeaderLines(binding.Kind, record.Values)
				if convErr != nil {
					setAuthCapability(plan, targetID, assessment.StateUnavailable, "credential fields are not valid HTTP headers")
					continue
				}
				if expired, at := expiredBearerJWT(lines, time.Now()); expired {
					setAuthVerification(plan, targetID, assessment.StateFailed, "the supplied token expired at "+at.UTC().Format("2006-01-02 15:04 UTC")+"; paste a fresh token; authenticated scanning was skipped")
					continue
				}
				positive, verifyErr := authProbeResult{}, error(nil)
				if record.BrowserStorage != nil || binding.VerifyBrowser {
					verifyErr = s.verifyBrowserCredential(ctx, target.Value, verifyURL, binding.VerifyMarker, lines, record.BrowserStorage, true)
				} else {
					positive, verifyErr = probeHeaderSession(ctx, verifyURL, binding.VerifyMarker, lines, target.Value)
				}

				if record.BrowserStorage == nil && !binding.VerifyBrowser && verifyErr == nil && binding.VerifyMarker != "" {
					negativeMarker := binding.NegativeMarker
					if negativeMarker == "" {
						negativeMarker = binding.VerifyMarker
					}
					verifyErr = verifyNegativeControl(ctx, scope, verifyURL, negativeMarker)
				} else if record.BrowserStorage == nil && !binding.VerifyBrowser && verifyErr == nil {
					verifyErr = verifyAnonymousContrast(ctx, scope, verifyURL, positive)
				}
				if verifyErr != nil {
					// With no verification URL, marker or browser check requested, a
					// target that answered but could not prove access (an API root
					// returning 404, an identical anonymous page) still gets the
					// credential, recorded as not verified. Pasted tokens from logins
					// that cannot be automated (for example NDI) depend on this.
					asked := binding.VerifyURL != "" || binding.VerifyMarker != "" || binding.VerifyBrowser || record.BrowserStorage != nil
					if asked || isProbeTransportError(verifyErr) {
						setAuthVerification(plan, targetID, assessment.StateFailed, "credential verification failed ("+verifyErr.Error()+"); authenticated scanning was skipped")
						continue
					}
					unverifiedReason = "credential applied, but access to this target was not verified (no verification URL supplied; " + verifyErr.Error() + ")"
				}
			}
			headersByTarget[targetID] = append(headersByTarget[targetID], lines...)
			verificationReason := "target-bound credentials passed the configured authentication check"
			if binding.Kind != assessment.AccessFormLogin && binding.VerifyMarker == "" {
				verificationReason = "target-bound credentials passed the authenticated-versus-anonymous negative control (status or redirect differed)"
			} else {
				verificationReason += " and the unauthenticated negative control passed"
			}
			if binding.Kind == assessment.AccessTokenLogin {
				verificationReason = "shared token login succeeded; " + verificationReason
			}
			if unverifiedReason != "" {
				setAuthVerification(plan, targetID, assessment.StateAvailable, unverifiedReason)
			} else {
				setAuthVerification(plan, targetID, assessment.StateVerified, verificationReason)
			}
			for i := range plan.Jobs {
				if plan.Jobs[i].TargetID == targetID && (plan.Jobs[i].Scanner == "zap" || plan.Jobs[i].Scanner == "nuclei") {
					plan.Jobs[i].ExecutionMode = "authenticated"
				}
			}
			for i := range plan.Decisions {
				if plan.Decisions[i].TargetID == targetID && (plan.Decisions[i].Scanner == "zap" || plan.Decisions[i].Scanner == "nuclei") {
					plan.Decisions[i].ExecutionMode = "authenticated"
				}
			}
		}
	}
	if len(tokenSessions) > 0 {
		s.tokenSessions.Store(plan, tokenSessions)
	}
	for i := range plan.Jobs {
		if (plan.Jobs[i].Scanner == "zap" || plan.Jobs[i].Scanner == "nuclei") && plan.Jobs[i].ExecutionMode != "authenticated" && hasBlockingAuth(plan.Capabilities, plan.Jobs[i].TargetID) {
			plan.Jobs[i].State = scanner.PlanSkipped
			plan.Jobs[i].Reason = "authenticated scan skipped: " + blockingAuthReason(plan.Capabilities, plan.Jobs[i].TargetID)
		}
	}
	return headersByTarget, nil
}

// assessmentAuthRefreshers rechecks the complete target-bound header set while
// ZAP is running. Form sessions get a fresh login each time their marker
// disappears, up to maxSessionRenewals per target; the next expiry stops
// authenticated work instead of silently downgrading it. Refreshes repeat only
// the positive check, never the negative control.
func (s *Server) assessmentAuthRefreshers(plan *scanner.AssessmentPlan, headers map[string][]string) (map[string]func(context.Context, []string) ([]string, error), error) {
	refreshers := map[string]func(context.Context, []string) ([]string, error){}
	if plan != nil && len(plan.AuthContexts) > 0 {
		for _, auth := range plan.AuthContexts {
			if auth.Primary && auth.State == assessment.StateVerified && auth.Refresh != nil {
				refreshers[auth.TargetID] = auth.Refresh
			}
		}
		return refreshers, nil
	}

	var tokenSessions map[string]*tokenSession
	if raw, ok := s.tokenSessions.LoadAndDelete(plan); ok {
		tokenSessions, _ = raw.(map[string]*tokenSession)
	}
	if len(headers) == 0 {
		return refreshers, nil
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		return nil, fmt.Errorf("authenticated session renewal is unavailable")
	}
	for _, target := range plan.Config.Targets {
		if len(headers[target.ID]) == 0 {
			continue
		}
		if refresh := tokenTargetRefresher(plan, target, tokenSessions); refresh != nil {
			refreshers[target.ID] = refresh
			continue
		}
		var verifyURL, marker string
		var formValues map[string]string
		var browserStorage *credentials.BrowserStorage
		var verifyBrowser bool
		for _, binding := range plan.Config.Access {
			if !webAuthenticationKind(binding.Kind) {
				continue
			}
			for _, id := range binding.TargetIDs {
				if id != target.ID {
					continue
				}
				if record, err := vault.Get(binding.CredentialID, target.ID); err == nil && record.BrowserStorage != nil {
					browserStorage = record.BrowserStorage
				}
				verifyBrowser = verifyBrowser || binding.VerifyBrowser
				if verifyURL == "" {
					verifyURL, marker = binding.VerifyURL, binding.VerifyMarker
				}
				if binding.Kind == assessment.AccessFormLogin {
					if formValues != nil {
						return nil, fmt.Errorf("multiple form sessions for one target are unsupported")
					}
					record, getErr := vault.Get(binding.CredentialID, target.ID)
					if getErr != nil || record.Kind != assessment.AccessFormLogin {
						return nil, fmt.Errorf("form session renewal credential is unavailable")
					}
					formValues = record.Values
					verifyURL, marker = binding.VerifyURL, binding.VerifyMarker
				}
			}
		}
		appURL := target.Value
		if verifyURL == "" {
			verifyURL = appURL
		}
		unverified := false
		for _, capability := range plan.Capabilities {
			if capability.Capability == assessment.CapAuthWeb && capability.TargetID == target.ID && capability.State == assessment.StateAvailable {
				unverified = true
			}
		}
		// Concurrent jobs on one target share the renewal budget; the lock also
		// keeps two of them from logging in at the same time.
		var mu sync.Mutex
		renewals := 0
		refreshers[target.ID] = func(ctx context.Context, current []string) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			// A pasted bearer JWT that has passed its exp claim cannot be renewed
			// without a login Xalgorix can perform; stop authenticated work.
			if formValues == nil {
				if expired, at := expiredBearerJWT(current, time.Now()); expired {
					return nil, fmt.Errorf("the supplied token expired at %s; paste a fresh token to continue authenticated testing", at.UTC().Format("2006-01-02 15:04 UTC"))
				}
			}
			if unverified {
				// Access was never verified, so there is no check to repeat.
				return current, nil
			}
			if browserStorage != nil || verifyBrowser {
				if err := s.verifyBrowserCredential(ctx, appURL, verifyURL, marker, current, browserStorage, false); err != nil {
					return nil, fmt.Errorf("browser authentication checkpoint failed")
				}
				return current, nil
			}
			if marker != "" {
				if err := verifyHeaderSession(ctx, verifyURL, marker, current, appURL); err == nil {
					return current, nil
				}
			} else if positive, err := probeHeaderSession(ctx, verifyURL, "", current, appURL); err == nil {
				if contrastErr := verifyAnonymousContrast(ctx, applicationScope(appURL), verifyURL, positive); contrastErr == nil {
					return current, nil
				}
			}
			if formValues == nil {
				return nil, fmt.Errorf("authenticated session expired or verification failed")
			}
			if renewals >= maxSessionRenewals {
				return nil, fmt.Errorf("authenticated session expired again after %d renewals; renewal limit reached", maxSessionRenewals)
			}
			renewals++
			var cookie string
			if strings.EqualFold(strings.TrimSpace(formValues["submit_format"]), "browser") {
				ch, _, err := s.captureBrowserLoginSession(ctx, appURL, verifyURL, marker, formValues)
				if err != nil {
					return nil, fmt.Errorf("authenticated session renewal failed")
				}
				cookie = ch
			} else {
				ch, err := verifyFormSession(ctx, appURL, verifyURL, marker, formValues)
				if err != nil {
					return nil, fmt.Errorf("authenticated session renewal failed")
				}
				cookie = ch
			}
			next := append([]string(nil), current...)
			for i, line := range next {
				if strings.HasPrefix(strings.ToLower(line), "cookie:") {
					next[i] = cookie
					return next, nil
				}
			}
			return nil, fmt.Errorf("authenticated session cookie is missing")
		}
	}
	return refreshers, nil
}

func webAuthenticationKind(kind assessment.AccessKind) bool {
	return kind.IsWebApplication()
}

func credentialHeaderLines(kind assessment.AccessKind, values map[string]string) ([]string, error) {
	lines := make([]string, 0, len(values))
	for name, value := range values {
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "" || value == "" || hasUnsafeHeaderValue(value) || strings.ContainsAny(name, "\r\n\x00") {
			return nil, fmt.Errorf("invalid header")
		}
		if !validHTTPHeaderName(name) {
			return nil, fmt.Errorf("invalid header name")
		}
		if kind == assessment.AccessBearerToken && !strings.EqualFold(name, "Authorization") {
			continue
		}
		lines = append(lines, name+": "+value)
	}
	if kind == assessment.AccessBearerToken {
		if len(lines) == 0 {
			if token := strings.TrimSpace(values["token"]); token != "" {
				lines = append(lines, "Authorization: Bearer "+token)
			}
		}
		for i := range lines {
			parts := strings.SplitN(lines[i], ":", 2)
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(parts[1])), "bearer ") {
				lines[i] = parts[0] + ": Bearer " + strings.TrimSpace(parts[1])
			}
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no HTTP header values")
	}
	sort.Strings(lines)
	return lines, nil
}

func hasUnsafeHeaderValue(value string) bool {
	for _, r := range value {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return true
		}
	}
	return false
}

func validHTTPHeaderName(name string) bool {
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return name != ""
}

type authProbeResult struct {
	StatusCode int
	FinalURL   string
}

func verifyHeaderSession(ctx context.Context, verifyURL, marker string, lines []string, appURL string) error {
	_, err := probeHeaderSession(ctx, verifyURL, marker, lines, appURL)
	return err
}

func probeHeaderSession(ctx context.Context, verifyURL, marker string, lines []string, appURL string) (authProbeResult, error) {
	var result authProbeResult
	scope := applicationScope(appURL)
	if !urlWithinScope(scope, verifyURL) {
		return result, fmt.Errorf("verification URL outside scope")
	}
	u, _ := url.Parse(verifyURL)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !urlWithinScope(scope, req.URL.String()) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, fmt.Errorf("invalid verification request")
	}
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return result, fmt.Errorf("invalid credential header")
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	resp, err := client.Do(req)
	if err != nil {
		return result, describeProbeTransportError(u.Hostname(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		path := u.Path
		if path == "" {
			path = "/"
		}
		return result, fmt.Errorf("verification returned non-success status (HTTP %d at %s)", resp.StatusCode, path)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return result, fmt.Errorf("verification response could not be read")
	}
	if marker != "" && !strings.Contains(string(body), marker) {
		return result, fmt.Errorf("verification marker not found")
	}
	result.StatusCode, result.FinalURL = resp.StatusCode, resp.Request.URL.String()
	return result, nil
}

// urlWithinApplication reports whether candidate is inside the origin and path
// boundary of appURL. The comparison is the shared assessment.AppScope matcher
// (default ports normalized, host case-insensitive, dot segments resolved).
func urlWithinApplication(appURL, candidate string) bool {
	return urlWithinScope(applicationScope(appURL), candidate)
}

// urlWithinScope keeps the stricter request rules of the login and
// verification flows on top of the scope matcher: no query string, fragment
// or embedded credentials.
func urlWithinScope(scope assessment.AppScope, candidate string) bool {
	u, err := url.Parse(candidate)
	if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.HasSuffix(candidate, "#") || strings.HasSuffix(candidate, "?") {
		return false
	}
	ok, _ := scope.Allows(candidate)
	return ok
}

func setAuthCapability(plan *scanner.AssessmentPlan, target string, state assessment.EvidenceState, reason string) {
	for i := range plan.Capabilities {
		if plan.Capabilities[i].Capability == assessment.CapAuthWeb && plan.Capabilities[i].TargetID == target {
			plan.Capabilities[i].State = state
			plan.Capabilities[i].Reason = reason
		}
	}
}

// setAuthVerification records the outcome of a verification that actually
// ran, marking the evidence as coming from the probe itself.
func setAuthVerification(plan *scanner.AssessmentPlan, target string, state assessment.EvidenceState, reason string) {
	setAuthCapability(plan, target, state, reason)
	for i := range plan.Capabilities {
		if plan.Capabilities[i].Capability == assessment.CapAuthWeb && plan.Capabilities[i].TargetID == target {
			plan.Capabilities[i].Provenance = authVerificationProvenance
		}
	}
}

// blockingAuthState reports whether an authenticated-web state forbids
// running authenticated jobs: nothing could be verified (unavailable), the
// verification was rejected (failed), or the session was lost (expired).
func blockingAuthState(state assessment.EvidenceState) bool {
	return state == assessment.StateUnavailable || state == assessment.StateFailed || state == assessment.StateExpired
}

func hasBlockingAuth(all []assessment.CapabilityEvidence, target string) bool {
	for _, e := range all {
		if e.Capability == assessment.CapAuthWeb && e.TargetID == target && blockingAuthState(e.State) {
			return true
		}
	}
	return false
}

func blockingAuthReason(all []assessment.CapabilityEvidence, target string) string {
	for _, evidence := range all {
		if evidence.Capability == assessment.CapAuthWeb && evidence.TargetID == target && blockingAuthState(evidence.State) {
			return evidence.Reason
		}
	}
	return "credential verification failed or is unsupported"
}

// assessmentURLScopes returns the application scope of every URL target.
func assessmentURLScopes(cfg assessment.AssessmentConfig) []assessment.AppScope {
	var scopes []assessment.AppScope
	for _, target := range cfg.Targets {
		if target.Kind == assessment.KindURL {
			scopes = append(scopes, assessment.AppScopeForTarget(cfg, target.ID))
		}
	}
	return scopes
}

// probeTransportError means the verification request never got an HTTP
// answer (DNS, connection, TLS or timeout). Applying a credential to a target
// the scanner cannot reach proves nothing, so callers treat it as a failure.
type probeTransportError struct{ msg string }

func (e probeTransportError) Error() string { return e.msg }

func describeProbeTransportError(host string, err error) error {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &dnsErr):
		return probeTransportError{"could not resolve " + host + " from the scanner (check DNS, or add the host to the container's extra_hosts)"}
	case errors.As(err, &certErr):
		return probeTransportError{"the TLS certificate of " + host + " was not trusted by the scanner"}
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return probeTransportError{"verification request to " + host + " timed out"}
	default:
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return probeTransportError{"could not connect to " + host + " from the scanner"}
		}
		return probeTransportError{"verification request to " + host + " failed"}
	}
}

// isProbeTransportError reports whether verification never reached the target.
func isProbeTransportError(err error) bool {
	var transport probeTransportError
	return errors.As(err, &transport)
}

// expiredBearerJWT reports whether an Authorization bearer header carries a JWT
// whose exp claim has passed. The signature is not checked; exp only times the
// session.
func expiredBearerJWT(lines []string, now time.Time) (bool, time.Time) {
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Authorization") {
			continue
		}
		token := strings.TrimSpace(value)
		if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
			token = strings.TrimSpace(token[7:])
		}
		if exp := jwtExpiry(token); !exp.IsZero() && !now.Before(exp) {
			return true, exp
		}
	}
	return false, time.Time{}
}

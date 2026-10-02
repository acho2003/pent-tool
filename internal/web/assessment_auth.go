package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
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
func (s *Server) prepareAssessmentAuthentication(ctx context.Context, plan *scanner.AssessmentPlan) (map[string][]string, error) {
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
			if !urlWithinApplication(target.Value, binding.VerifyURL) || !scopeAllowsRequest(scope, binding.VerifyURL) {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "verification URL is outside the application origin or path boundary")
				continue
			}
			negativeMarker := binding.NegativeMarker
			if negativeMarker == "" {
				negativeMarker = binding.VerifyMarker
			}
			if binding.VerifyMarker == "" || negativeMarker == "" {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "no verification marker is configured")
				continue
			}
			var lines []string
			if binding.Kind == assessment.AccessFormLogin {
				cookieHeader, loginErr := verifyFormSession(ctx, target.Value, binding.VerifyURL, binding.VerifyMarker, record.Values)
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
				lines = []string{cookieHeader}
			} else {
				var convErr error
				lines, convErr = credentialHeaderLines(binding.Kind, record.Values)
				if convErr != nil {
					setAuthCapability(plan, targetID, assessment.StateUnavailable, "credential fields are not valid HTTP headers")
					continue
				}
				if verifyErr := verifyHeaderSession(ctx, binding.VerifyURL, binding.VerifyMarker, lines, target.Value); verifyErr != nil {
					setAuthVerification(plan, targetID, assessment.StateFailed, "credential verification failed ("+verifyErr.Error()+"); authenticated scanning was skipped")
					continue
				}
			}
			// The negative control runs once per verification, after the positive
			// check; session refreshes only repeat the positive check.
			if controlErr := verifyNegativeControl(ctx, scope, binding.VerifyURL, negativeMarker); controlErr != nil {
				setAuthVerification(plan, targetID, assessment.StateFailed, "negative control failed ("+controlErr.Error()+"); the marker does not prove an authenticated session, so authenticated scanning was skipped")
				continue
			}
			headersByTarget[targetID] = append(headersByTarget[targetID], lines...)
			setAuthVerification(plan, targetID, assessment.StateVerified, "target-bound credentials passed the configured verification check and an unauthenticated request did not show the marker (negative control passed)")
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
		var verifyURL, marker string
		var formValues map[string]string
		for _, binding := range plan.Config.Access {
			if !webAuthenticationKind(binding.Kind) {
				continue
			}
			for _, id := range binding.TargetIDs {
				if id != target.ID {
					continue
				}
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
		// Concurrent jobs on one target share the renewal budget; the lock also
		// keeps two of them from logging in at the same time.
		var mu sync.Mutex
		renewals := 0
		refreshers[target.ID] = func(ctx context.Context, current []string) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			if err := verifyHeaderSession(ctx, verifyURL, marker, current, appURL); err == nil {
				return current, nil
			}
			if formValues == nil {
				return nil, fmt.Errorf("authenticated session expired or verification failed")
			}
			if renewals >= maxSessionRenewals {
				return nil, fmt.Errorf("authenticated session expired again after %d renewals; renewal limit reached", maxSessionRenewals)
			}
			renewals++
			cookie, err := verifyFormSession(ctx, appURL, verifyURL, marker, formValues)
			if err != nil {
				return nil, fmt.Errorf("authenticated session renewal failed")
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
	switch kind {
	case assessment.AccessApplicationHeaders, assessment.AccessApplicationCookies, assessment.AccessBearerToken, assessment.AccessAPIKey, assessment.AccessFormLogin:
		return true
	}
	return false
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

func verifyHeaderSession(ctx context.Context, verifyURL, marker string, lines []string, appURL string) error {
	scope := applicationScope(appURL)
	if !urlWithinScope(scope, verifyURL) {
		return fmt.Errorf("verification URL outside scope")
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
		return fmt.Errorf("invalid verification request")
	}
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("invalid credential header")
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("verification request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("verification returned non-success status")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || !strings.Contains(string(body), marker) {
		return fmt.Errorf("verification marker not found")
	}
	return nil
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

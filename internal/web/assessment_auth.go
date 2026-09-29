package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// prepareAssessmentAuthentication verifies target-bound static headers before
// any typed scanner receives them. Secret values remain in runtime memory only.
func (s *Server) prepareAssessmentAuthentication(ctx context.Context, plan *scanner.AssessmentPlan) (map[string][]string, error) {
	headersByTarget := map[string][]string{}
	if plan == nil || len(plan.Config.Access) == 0 {
		return headersByTarget, nil
	}
	for i := range plan.Jobs {
		if plan.Jobs[i].Scanner == "zap" {
			plan.Jobs[i].ExecutionMode = "unauthenticated"
		}
	}
	for i := range plan.Decisions {
		if plan.Decisions[i].Scanner == "zap" {
			plan.Decisions[i].ExecutionMode = "unauthenticated"
		}
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		for _, binding := range plan.Config.Access {
			for _, targetID := range binding.TargetIDs {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "credential vault is unavailable; authenticated scanning was skipped")
			}
		}
		for i := range plan.Jobs {
			if plan.Jobs[i].Scanner == "zap" && hasUnavailableAuth(plan.Capabilities, plan.Jobs[i].TargetID) {
				plan.Jobs[i].State = scanner.PlanSkipped
				plan.Jobs[i].Reason = "authenticated scan skipped because credential verification was unavailable"
			}
		}
		return headersByTarget, nil
	}
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessApplicationHeaders && binding.Kind != assessment.AccessApplicationCookies && binding.Kind != assessment.AccessBearerToken && binding.Kind != assessment.AccessAPIKey {
			for _, targetID := range binding.TargetIDs {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "this credential type is not yet supported by the execution adapter")
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
			lines, convErr := credentialHeaderLines(binding.Kind, record.Values)
			if convErr != nil {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "credential fields are not valid HTTP headers")
				continue
			}
			if !urlWithinApplication(target.Value, binding.VerifyURL) {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "verification URL is outside the application origin or path boundary")
				continue
			}
			if verifyErr := verifyHeaderSession(ctx, binding.VerifyURL, binding.VerifyMarker, lines, target.Value); verifyErr != nil {
				setAuthCapability(plan, targetID, assessment.StateUnavailable, "credential verification failed; authenticated scanning was skipped")
				continue
			}
			headersByTarget[targetID] = append(headersByTarget[targetID], lines...)
			setAuthCapability(plan, targetID, assessment.StateVerified, "target-bound credentials passed the configured verification check")
			for i := range plan.Jobs {
				if plan.Jobs[i].TargetID == targetID && plan.Jobs[i].Scanner == "zap" {
					plan.Jobs[i].ExecutionMode = "authenticated"
				}
			}
			for i := range plan.Decisions {
				if plan.Decisions[i].TargetID == targetID && plan.Decisions[i].Scanner == "zap" {
					plan.Decisions[i].ExecutionMode = "authenticated"
				}
			}
		}
	}
	for i := range plan.Jobs {
		if plan.Jobs[i].Scanner == "zap" && plan.Jobs[i].ExecutionMode != "authenticated" && hasUnavailableAuth(plan.Capabilities, plan.Jobs[i].TargetID) {
			plan.Jobs[i].State = scanner.PlanSkipped
			plan.Jobs[i].Reason = "authenticated scan skipped because credential verification failed or is unsupported"
		}
	}
	return headersByTarget, nil
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
	if !urlWithinApplication(appURL, verifyURL) {
		return fmt.Errorf("verification URL outside scope")
	}
	u, _ := url.Parse(verifyURL)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !urlWithinApplication(appURL, req.URL.String()) {
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

func urlWithinApplication(appURL, candidate string) bool {
	app, err1 := url.Parse(appURL)
	u, err2 := url.Parse(candidate)
	if err1 != nil || err2 != nil || app.Host == "" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || !strings.EqualFold(app.Scheme, u.Scheme) || !strings.EqualFold(app.Host, u.Host) {
		return false
	}
	base := strings.TrimSuffix(app.EscapedPath(), "/")
	path := u.EscapedPath()
	return base == "" || path == base || strings.HasPrefix(path, base+"/")
}

func setAuthCapability(plan *scanner.AssessmentPlan, target string, state assessment.EvidenceState, reason string) {
	for i := range plan.Capabilities {
		if plan.Capabilities[i].Capability == assessment.CapAuthWeb && plan.Capabilities[i].TargetID == target {
			plan.Capabilities[i].State = state
			plan.Capabilities[i].Reason = reason
		}
	}
}

func hasUnavailableAuth(all []assessment.CapabilityEvidence, target string) bool {
	for _, e := range all {
		if e.Capability == assessment.CapAuthWeb && e.TargetID == target && e.State == assessment.StateUnavailable {
			return true
		}
	}
	return false
}

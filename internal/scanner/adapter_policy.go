package scanner

import (
	"context"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// Policy reasons for optional adapters whose generated traffic cannot comply
// with the default low-impact request policy. They are shown verbatim at plan
// preview and on the refused run, so they explain the gap to the operator.
const (
	wapitiPolicyReason  = "Wapiti is restricted under the default low-impact policy: its crawler submits discovered forms and its default modules include SSRF with an external callback; it runs only with a reviewed GET-only module allowlist when the target is declared a test environment"
	niktoPolicyReason   = "Nikto is restricted because route exclusions are configured: it requests its own fixed test paths and cannot honour excluded routes"
	testsslPolicyReason = "testssl is restricted because the approved boundary is below the origin root or excludes it: testssl issues its own HTTP request to the origin root, which would fall outside the approved paths"
)

// AdapterPolicyRestriction reports whether the request policy of cfg forbids
// the optional adapter id, with the reason to show as its coverage gap. The
// planner uses it to skip the job at preview; the adapter builders apply the
// same rule at execution time from the Request (requestPolicyRestriction).
// Exclusions are counted assessment-wide, which can only restrict more.
func AdapterPolicyRestriction(id string, cfg assessment.AssessmentConfig) (restricted bool, reason string) {
	return adapterPolicyRestriction(id, cfg.TestEnvironment, len(cfg.Exclusions) > 0)
}

// requestPolicyRestriction is AdapterPolicyRestriction evaluated on the
// runtime Request. A nil AppScope is the legacy path and carries no
// exclusions.
func requestPolicyRestriction(id string, req Request) (bool, string) {
	excluded := req.AppScope != nil && len(req.AppScope.Exclusions()) > 0
	if restricted, reason := adapterPolicyRestriction(id, req.TestEnvironment, excluded); restricted {
		return true, reason
	}
	if id == "testssl" && req.AppScope != nil && originRootOutsideBoundary(req) {
		return true, testsslPolicyReason
	}
	return false, ""
}

// originRootOutsideBoundary reports whether any approved origin is bounded below
// its root, or the root request is excluded, so a tool that always requests "/"
// would leave the approved paths.
func originRootOutsideBoundary(req Request) bool {
	for _, origin := range req.AppScope.Origins() {
		if origin.PathPrefix != "" && origin.PathPrefix != "/" {
			return true
		}
		if excluded, _ := req.AppScope.Excluded("GET", origin.Origin()+"/"); excluded {
			return true
		}
	}
	return false
}

func adapterPolicyRestriction(id string, testEnvironment, hasExclusions bool) (bool, string) {
	switch id {
	case "wapiti":
		if !testEnvironment {
			return true, wapitiPolicyReason
		}
	case "nikto":
		if hasExclusions {
			return true, niktoPolicyReason
		}
	}
	return false, ""
}

// executePolicySpec runs spec like executeSpec and, when the request policy
// restricts the adapter (its builder then returned the policy reason as
// notApp), tags the not-applicable run and its emitted event with GapExcluded
// so coverage reports a policy gap rather than an inapplicable target.
func executePolicySpec(ctx context.Context, name string, req Request, cfg Config, spec commandSpec, emit EmitFunc) Run {
	if restricted, _ := requestPolicyRestriction(name, req); !restricted {
		return executeSpec(ctx, name, req, cfg, spec, emit)
	}
	tagged := emit
	if emit != nil {
		tagged = func(event Event) {
			event.Run.GapKind = GapExcluded
			emit(event)
		}
	}
	run := executeSpec(ctx, name, req, cfg, spec, tagged)
	run.GapKind = GapExcluded
	return run
}

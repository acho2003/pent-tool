package scanner

import "github.com/acho2003/pent-tool/internal/assessment"

// LimitationLoginFallback: the target's configured login failed, so this run
// used no credentials. It covers only what an anonymous visitor can reach;
// authenticated pages, APIs and checks are missing from it.
const LimitationLoginFallback = "login_failed_unauthenticated_fallback"

const loginFallbackReason = "The configured login for this target failed, so this ran without credentials. It covers only what an anonymous visitor can reach; authenticated pages and APIs were not tested."

func appendLoginFallbackLimitation(limitations []RunLimitation) []RunLimitation {
	for _, existing := range limitations {
		if existing.Kind == LimitationLoginFallback {
			return limitations
		}
	}
	return append(limitations, RunLimitation{Kind: LimitationLoginFallback, Reason: loginFallbackReason})
}

// loginFallbackEligible reports whether a web scanner job may run without
// credentials after its target's login failed. Jobs whose consent or purpose
// is bound to an authenticated identity stay skipped: the access matrix
// compares identities, approved writes and the bounded Wapiti POST campaign
// were approved for the primary identity, and Schemathesis write fuzzing was
// approved as an authenticated test-environment campaign.
func loginFallbackEligible(job PlanJob, cfg assessment.AssessmentConfig) bool {
	switch job.Scanner {
	case "zap", "nuclei", "dalfox":
		return true
	case "wapiti":
		return job.FuzzApprovalID == ""
	case "schemathesis":
		return !cfg.APIWriteFuzz
	}
	return false
}

package assessment

import "testing"

func TestNextjsLimitsRejectNegativeAndExcessiveValues(t *testing.T) {
	for _, options := range []NextjsScanOptions{{MaxPages: -1}, {MaxScripts: 501}, {MaxRouteChecks: 501}, {MaxRequests: 5001}, {MaxResponseBytes: 257 << 20}} {
		found := false
		for _, problem := range Validate(AssessmentConfig{Nextjs: options}) {
			if problem.Code == "nextjs.limit.invalid" && problem.Blocking {
				found = true
			}
		}
		if !found {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
}

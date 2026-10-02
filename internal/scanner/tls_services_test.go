package scanner

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestTLSJobsUseEachApprovedServiceAndPreservePort(t *testing.T) {
	cfg := assessment.Normalize(assessment.AssessmentConfig{
		Types:   []assessment.Type{assessment.TypeWebApplication},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/app"}},
		ApprovedOrigins: []assessment.ApprovedOrigin{
			{TargetID: "app", Scheme: "https", Host: "app.example.test", Port: 443, PathPrefix: "/app"},
			{TargetID: "app", Scheme: "https", Host: "api.example.test", Port: 8443, PathPrefix: "/v1"},
			{TargetID: "app", Scheme: "http", Host: "app.example.test", Port: 80, PathPrefix: "/app"},
		},
	})
	jobs := expandTLSServiceJobs(cfg, []PlanJob{{ID: "testssl:app:testssl", Scanner: "testssl", TargetID: "app", Target: cfg.Targets[0].Value, State: PlanSelected}})
	if len(jobs) != 2 || jobs[0].Target != "https://api.example.test:8443" || jobs[1].Target != "https://app.example.test" || jobs[0].ID == jobs[1].ID {
		t.Fatalf("TLS services not preserved: %+v", jobs)
	}
}

func TestTLSJobsSkipPlainHTTPOnlyApplication(t *testing.T) {
	cfg := assessment.Normalize(assessment.AssessmentConfig{Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "http://app.example.test/"}}})
	jobs := expandTLSServiceJobs(cfg, []PlanJob{{ID: "tls", Scanner: "testssl", TargetID: "app", Target: cfg.Targets[0].Value, State: PlanSelected}})
	if len(jobs) != 1 || jobs[0].State != PlanSkipped {
		t.Fatalf("HTTP-only target gained TLS service: %+v", jobs)
	}
}

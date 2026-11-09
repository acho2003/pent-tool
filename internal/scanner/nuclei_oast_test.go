package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestInteractshServerMustBeSelfHosted(t *testing.T) {
	for _, tc := range []struct {
		server string
		ok     bool
	}{
		{"https://oast.example.org", true},
		{"http://oast:80", true},
		{"", false},
		{"https://oast.pro", false},
		{"https://abc.oast.fun", false},
		{"https://interact.sh", false},
		{"https://user:pw@oast.example.org", false},
		{"https://oast.example.org/path", false},
		{"ftp://oast.example.org", false},
	} {
		if got := InteractshUnavailableReason(tc.server) == ""; got != tc.ok {
			t.Errorf("%q: available=%v want %v (%s)", tc.server, got, tc.ok, InteractshUnavailableReason(tc.server))
		}
	}
}

func TestNucleiOASTArgsSelectOnlyCallbackTemplatesAgainstTheConfiguredServer(t *testing.T) {
	policy := nucleiPolicyArgs(Config{RateRPS: 5})
	args, err := nucleiOASTArgs(policy, "https://oast.example.org/", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if slices.Contains(args, "-ni") {
		t.Fatal("interactsh must be enabled for the OAST variant")
	}
	if !strings.Contains(joined, "-iserver https://oast.example.org ") || !strings.Contains(joined, "-itoken secret-token") {
		t.Fatalf("the configured server must be explicit, never Nuclei's public default: %s", joined)
	}
	if !strings.Contains(joined, "-tags oast,oob,interactsh") {
		t.Fatalf("only OAST templates may be selected: %s", joined)
	}
	var excluded string
	for i := range args {
		if args[i] == "-etags" {
			excluded = args[i+1]
		}
	}
	for _, tag := range []string{"rce", "dos", "intrusive", "bruteforce"} {
		if !strings.Contains(","+excluded+",", ","+tag+",") {
			t.Errorf("tag %q must stay excluded: %s", tag, excluded)
		}
	}
	if strings.Contains(","+excluded+",", ",oast,") {
		t.Errorf("oast must not be both selected and excluded: %s", excluded)
	}
	if !strings.Contains(joined, "-dr") || !strings.Contains(joined, "-pt http") {
		t.Fatalf("the other reviewed policy flags must be kept: %s", joined)
	}
	if _, err := nucleiOASTArgs(policy, "https://oast.pro", ""); err == nil {
		t.Fatal("a public interactsh server must be refused")
	}
	if _, err := nucleiOASTArgs([]string{"-pt", "http"}, "https://oast.example.org", ""); err == nil {
		t.Fatal("a policy without -ni/-etags cannot be safely transformed")
	}
}

func TestOASTJobNeedsConsentAndASelfHostedServer(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, WorkflowVersion: "unified-v1", Types: []assessment.Type{assessment.TypeWebApplication},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	oastJobs := func(cfg assessment.AssessmentConfig, available bool) ([]PlanJob, AssessmentPlan) {
		plan := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"nuclei": true, NucleiOASTVariant: available}, UnavailabilityReasons: map[string]string{NucleiOASTVariant: "no server configured"}})
		var jobs []PlanJob
		for _, job := range plan.Jobs {
			if job.Variant == NucleiOASTVariant {
				jobs = append(jobs, job)
			}
		}
		return jobs, plan
	}
	if jobs, _ := oastJobs(cfg, true); len(jobs) != 0 {
		t.Fatalf("no consent must mean no OAST job: %+v", jobs)
	}
	cfg.OASTCallbacks = true
	jobs, plan := oastJobs(cfg, true)
	if len(jobs) != 1 || jobs[0].Scanner != "nuclei" || jobs[0].State != PlanSelected || jobs[0].Stage == "" {
		t.Fatalf("consent with a configured server must plan one Nuclei OAST job: %+v errors=%+v", jobs, plan.Errors)
	}
	if jobs, _ := oastJobs(cfg, false); len(jobs) != 1 || jobs[0].State != PlanUnavailable || jobs[0].Reason != "no server configured" {
		t.Fatalf("consent without a server must stay visible as unavailable: %+v", jobs)
	}
	legacy := cfg
	legacy.WorkflowVersion = ""
	if jobs, plan := oastJobs(legacy, true); len(jobs) != 0 || !slices.ContainsFunc(plan.Warnings, func(p assessment.Problem) bool { return p.Code == "oast.workflow_required" }) {
		t.Fatalf("legacy plans must warn instead of running OAST: %+v %+v", jobs, plan.Warnings)
	}
}

func TestBuildNucleiEnablesInteractshOnlyForTheOASTJob(t *testing.T) {
	req := Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}
	cfg := Config{NucleiPath: "nuclei", NucleiTemplatesDir: "/opt/nuclei-templates"}
	plain := strings.Join(buildNuclei(req, cfg).args, " ")
	if !strings.Contains(plain, " -ni ") || strings.Contains(plain, "-iserver") {
		t.Fatalf("ordinary Nuclei must keep interactsh disabled: %s", plain)
	}
	req.OASTServer = "https://oast.example.org"
	spec := buildNuclei(req, cfg)
	if spec.notApp != "" || !strings.Contains(strings.Join(spec.args, " "), "-iserver https://oast.example.org") || len(spec.limitations) != 2 || spec.limitations[1].Kind != "callback_window" {
		t.Fatalf("OAST job must use the configured server and record its limits: %+v", spec)
	}
	req.OASTServer = "https://oast.fun"
	if spec := buildNuclei(req, cfg); !strings.Contains(spec.notApp, "public Interactsh") {
		t.Fatalf("a public server must make the OAST job not applicable: %q", spec.notApp)
	}
}

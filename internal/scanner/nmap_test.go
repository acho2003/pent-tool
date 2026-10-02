package scanner

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestBuildNmapAcceptsNetworkTargetsAndRejectsUnsafeOnes(t *testing.T) {
	cfg := Config{NmapPath: "nmap", NmapTimeout: 60000000000}
	ok := map[string]string{
		"192.168.1.10":    "192.168.1.10",
		"10.0.0.0/24":     "10.0.0.0/24",
		"scanme.test":     "scanme.test",
		"host.example.io": "host.example.io",
	}
	for target, want := range ok {
		spec := buildNmap(Request{Target: target, ScanDir: t.TempDir()}, cfg)
		if spec.notApp != "" {
			t.Fatalf("%q was rejected: %s", target, spec.notApp)
		}
		arg, _ := argValue(spec.args, "--")
		if arg != want {
			t.Fatalf("%q scanned as %q, want %q (args=%v)", target, arg, want, spec.args)
		}
		if !hasArg(spec.args, "-sT") || !hasArg(spec.args, "-sV") || !hasArg(spec.args, "-oX") {
			t.Fatalf("%q missing service-detection/XML args: %v", target, spec.args)
		}
	}
	for _, bad := range []string{
		"", "http://192.168.1.10", "192.168.1.10:80", "10.0.0.5/24",
		"host.example.io/path", "a b", "evil.test;rm -rf", "-oG",
	} {
		if spec := buildNmap(Request{Target: bad, ScanDir: t.TempDir()}, cfg); spec.notApp == "" {
			t.Fatalf("unsafe nmap target accepted: %q -> %v", bad, spec.args)
		}
	}
	if spec := buildNmap(Request{Target: "192.168.1.10", ScanDir: t.TempDir()}, Config{NmapTimeout: 1}); spec.notApp == "" {
		t.Fatal("nmap with no configured path should be not-applicable")
	}
}

func TestBuildNiktoAcceptsBareNetworkHost(t *testing.T) {
	cfg := Config{NiktoPath: "nikto", NiktoTimeout: 60000000000}
	spec := buildNikto(Request{Target: "192.168.1.10", ScanDir: t.TempDir()}, cfg)
	if spec.notApp != "" {
		t.Fatalf("bare IP was rejected: %s", spec.notApp)
	}
	host, _ := argValue(spec.args, "-host")
	if host != "http://192.168.1.10/" {
		t.Fatalf("bare IP host = %q, want http://192.168.1.10/ (args=%v)", host, spec.args)
	}
	// An explicit URL keeps its scheme untouched.
	httpsSpec := buildNikto(Request{Target: "https://app.test/", ScanDir: t.TempDir()}, cfg)
	if h, _ := argValue(httpsSpec.args, "-host"); h != "https://app.test/" {
		t.Fatalf("URL host = %q, want https://app.test/", h)
	}
}

func TestPlannerRunsNmapAndOffersNiktoOnNetworkIP(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode:    assessment.ModeBlackBox,
		Types:   []assessment.Type{assessment.TypeNetwork},
		Targets: []assessment.Target{{ID: "t1", Kind: assessment.KindIP, Value: "192.0.2.10"}},
	}
	plan := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"nmap": true, "nikto": true}})
	var nmapState, niktoState PlanState = "", ""
	for _, d := range plan.Decisions {
		if d.TargetID != "t1" {
			continue
		}
		switch d.Scanner {
		case "nmap":
			nmapState = d.State
		case "nikto":
			niktoState = d.State
		}
	}
	if nmapState != PlanSelected {
		t.Fatalf("nmap on a network IP should be selected automatically, got %q", nmapState)
	}
	if niktoState != PlanOptional {
		t.Fatalf("nikto on a network IP should be offered as opt-in, got %q", niktoState)
	}
	// Explicitly selecting nikto creates a planned job on the IP target.
	cfg.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"nikto"}}
	selected := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"nikto": true}})
	if !hasPlannedJob(selected, "nikto", "t1") {
		t.Fatalf("explicitly selected nikto did not create a job: %+v", selected.Jobs)
	}
}

func hasPlannedJob(plan AssessmentPlan, scanner, targetID string) bool {
	for _, job := range plan.Jobs {
		if job.Scanner == scanner && job.TargetID == targetID {
			return true
		}
	}
	return false
}

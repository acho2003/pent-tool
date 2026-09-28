package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"slices"
	"testing"
)

func TestScannerRegistryPreservesLegacyCatalogAndAddsUnavailableAdapters(t *testing.T) {
	want := []string{"subfinder", "httpx", "nmap", "nuclei", "zap", "testssl", "openvas", "vuls", "trivy", "semgrep", "gitleaks", "osv"}
	var got []string
	for _, tool := range Catalog() {
		got = append(got, tool.Name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("legacy catalog changed: %v", got)
	}
	for _, id := range []string{"masscan", "nikto", "sqlmap", "lynis"} {
		d, ok := RegistryEntry(id)
		if !ok || d.Available {
			t.Errorf("%s should be registered and unavailable", id)
		}
	}
}

func TestPlanAssessmentBlackBoxNetworkDoesNotSelectCodeOrUnsupportedTools(t *testing.T) {
	plan := PlanAssessment(PlanInput{Config: assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork}, Targets: []assessment.Target{{ID: "host", Kind: assessment.KindIP, Value: "192.0.2.10"}}}})
	if len(plan.Errors) > 0 {
		t.Fatalf("unexpected errors: %+v", plan.Errors)
	}
	want := map[string]PlanState{"nmap": PlanSelected, "openvas": PlanSelected, "masscan": PlanUnavailable, "semgrep": PlanNotApplicable, "lynis": PlanNotApplicable}
	for id, state := range want {
		found := false
		for _, d := range plan.Decisions {
			targetMatches := d.TargetID == "host" || ((id == "semgrep" || id == "lynis") && d.TargetID == "")
			if d.Scanner == id && targetMatches {
				found = true
				if d.State != state {
					t.Errorf("%s state=%s want %s (%s)", id, d.State, state, d.Reason)
				}
			}
		}
		if !found {
			t.Errorf("missing decision for %s", id)
		}
	}
}

func TestPlanAssessmentGrayBoxBindsAuthAndSchemaToOneTarget(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/Portal/"}, {ID: "other", Kind: assessment.KindURL, Value: "https://other.example.test"}}, APIDefinitionIDs: []string{"spec1"}, Access: []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, CredentialID: "cred1"}}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	for _, d := range plan.Decisions {
		if d.Scanner == "zap" && d.TargetID == "app" && d.State == PlanSelected && d.ExecutionMode == "authenticated" {
			t.Errorf("unverified access must not be labeled authenticated: %+v", d)
		}
		if d.Scanner == "zap" && d.TargetID == "other" && d.ExecutionMode == "authenticated" {
			t.Errorf("credentials crossed target boundary: %+v", d)
		}
	}
}

func TestPlanAssessmentWhiteBoxDoesNotInventCredentialsAndCustomSelection(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeHost}, Targets: []assessment.Target{{ID: "host", Kind: assessment.KindHost, Value: "server.example.test"}}, ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"nmap"}}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	for _, d := range plan.Decisions {
		if d.Scanner == "vuls" && d.TargetID == "host" && d.State != PlanNotApplicable {
			t.Errorf("Vuls inferred missing SSH: %+v", d)
		}
	}
	if _, ok := RegistryEntry("does-not-exist"); ok {
		t.Fatal("unknown scanner unexpectedly registered")
	}
}

func TestPlanFingerprintStableAcrossCallsAndUnsupportedTypesExplainCoverage(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeKubernetes}, Targets: []assessment.Target{{ID: "cluster", Kind: assessment.KindKubernetesCluster, Value: "prod"}}}
	a := PlanAssessment(PlanInput{Config: cfg})
	b := PlanAssessment(PlanInput{Config: cfg})
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint {
		t.Fatalf("unstable fingerprint %q %q", a.Fingerprint, b.Fingerprint)
	}
	if len(a.Coverage) != 1 || a.Coverage[0].State != "not_applicable" {
		t.Fatalf("unexpected coverage: %+v", a.Coverage)
	}
}

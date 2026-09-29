package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"slices"
	"strings"
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

func TestMasscanRemainsOptionalAndRequiresInstalledAdapterAndExplicitSelection(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork},
		Targets:          []assessment.Target{{ID: "net", Kind: assessment.KindIP, Value: "192.0.2.10"}},
		ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"masscan"}},
	}
	unavailable := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"masscan": false}})
	if len(unavailable.Jobs) != 0 || !slices.ContainsFunc(unavailable.Decisions, func(d PlanDecision) bool { return d.Scanner == "masscan" && d.State == PlanUnavailable }) {
		t.Fatalf("unavailable Masscan was planned: %+v", unavailable)
	}
	available := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"masscan": true}})
	if len(available.Jobs) != 1 || available.Jobs[0].Scanner != "masscan" || available.Jobs[0].State != PlanSelected || !HasAssessmentRunner("masscan") {
		t.Fatalf("explicitly selected Masscan job missing: %+v", available)
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
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/Portal/"}, {ID: "other", Kind: assessment.KindURL, Value: "https://other.example.test"}}, APIDefinitions: []assessment.APIDefinitionBinding{{TargetID: "app", DefinitionID: "spec1"}}, Access: []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, CredentialID: "cred1"}}}
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

func TestPlanAssessmentTrivyUsesImageAndSBOMCapabilities(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeContainer, assessment.TypeDependencies}, Targets: []assessment.Target{{ID: "image", Kind: assessment.KindDockerImage, Value: "registry.test/app@sha256:" + strings.Repeat("a", 64)}, {ID: "sbom", Kind: assessment.KindSBOM, Value: "/data/bom.json"}}}
	plan := PlanAssessment(PlanInput{Config: cfg})
	if len(plan.Errors) != 0 {
		t.Fatalf("valid resources rejected: %+v", plan.Errors)
	}
	for _, id := range []string{"image", "sbom"} {
		found := false
		for _, job := range plan.Jobs {
			if job.Scanner == "trivy" && job.TargetID == id && job.State == PlanConditional {
				found = true
			}
		}
		if !found {
			t.Fatalf("Trivy %s job missing from plan: %+v", id, plan.Decisions)
		}
	}
}

func TestPlanFingerprintStableAcrossCallsAndUnsupportedTypesExplainCoverage(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Types: []assessment.Type{assessment.TypeKubernetes}, Targets: []assessment.Target{{ID: "cluster", Kind: assessment.KindKubernetesCluster, Value: "prod"}}}
	a := PlanAssessment(PlanInput{Config: cfg})
	b := PlanAssessment(PlanInput{Config: cfg})
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint {
		t.Fatalf("unstable fingerprint %q %q", a.Fingerprint, b.Fingerprint)
	}
	// A named kube-bench adapter now exists but is Available=false until installed,
	// so the Kubernetes type is covered-but-unavailable (was "no scanner exists").
	if len(a.Coverage) != 1 || a.Coverage[0].State != "unavailable" || !strings.Contains(a.Coverage[0].Reason, "unavailable") {
		t.Fatalf("unexpected coverage: %+v", a.Coverage)
	}
}

func TestOptionalScannerNeedsExplicitSelectionAndUnknownSelectionDoesNotCreateJobs(t *testing.T) {
	base := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/search?q=x"}}}
	defaultPlan := PlanAssessment(PlanInput{Config: base, Availability: map[string]bool{"nikto": true, "sqlmap": true}})
	for _, d := range defaultPlan.Decisions {
		if d.Scanner == "nikto" && d.TargetID == "app" && d.State != PlanOptional {
			t.Fatalf("Nikto should remain optional by default, got %+v", d)
		}
		if d.Scanner == "sqlmap" && d.TargetID == "app" && d.State != PlanOptional {
			t.Fatalf("SQLMap should remain opt-in by default, got %+v", d)
		}
	}

	base.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"sqlmap"}}
	selected := PlanAssessment(PlanInput{Config: base, Availability: map[string]bool{"sqlmap": true}})
	foundJob := false
	for _, job := range selected.Jobs {
		if job.Scanner == "sqlmap" && job.TargetID == "app" {
			foundJob = true
		}
	}
	if !foundJob {
		t.Fatalf("explicitly selected and available SQLMap should create a planned job: %+v", selected)
	}

	base.ScannerSelection.Variants = []string{"missing"}
	invalid := PlanAssessment(PlanInput{Config: base})
	if len(invalid.Errors) == 0 || len(invalid.Jobs) != 0 {
		t.Fatalf("invalid selection must block planning without jobs: %+v", invalid)
	}
}

func TestDomainSubdomainDiscoveryRequiresSeparateExplicitPermission(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork}, Targets: []assessment.Target{{ID: "domain", Kind: assessment.KindDomain, Value: "example.test"}}}
	withoutPermission := PlanAssessment(PlanInput{Config: cfg})
	foundDecision := false
	for _, d := range withoutPermission.Decisions {
		if d.Scanner == "subfinder" && d.TargetID == "domain" {
			foundDecision = true
			if d.State != PlanOptional || d.ReasonCode != "discovery.subdomain_opt_in_required" {
				t.Fatalf("subfinder state without permission = %+v", d)
			}
		}
	}
	if !foundDecision {
		t.Fatal("missing target-bound Subfinder decision")
	}
	for _, job := range withoutPermission.Jobs {
		if job.Scanner == "subfinder" {
			t.Fatal("subfinder job created without explicit subdomain permission")
		}
	}

	cfg.SubdomainDiscovery = true
	withPermission := PlanAssessment(PlanInput{Config: cfg})
	found := false
	for _, job := range withPermission.Jobs {
		if job.Scanner == "subfinder" && job.TargetID == "domain" {
			found = true
		}
	}
	if !found {
		t.Fatalf("authorized subdomain discovery job missing: %+v", withPermission.Decisions)
	}
}

func TestPlannerRequiresResolvableTargetBoundCredentialAndNeverClaimsVerifiedAuth(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode:    assessment.ModeGrayBox,
		Types:   []assessment.Type{assessment.TypeWebApplication},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}, {ID: "other", Kind: assessment.KindURL, Value: "https://other.example.test/"}},
		Access:  []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessApplicationHeaders, CredentialID: "cred-1"}},
	}
	missing := PlanAssessment(PlanInput{Config: cfg})
	if !slices.ContainsFunc(missing.Capabilities, func(e assessment.CapabilityEvidence) bool {
		return e.TargetID == "app" && e.Capability == assessment.CapAuthWeb && e.State == assessment.StateUnavailable
	}) {
		t.Fatalf("unresolved credential was treated as available: %+v", missing.Capabilities)
	}
	wrongKind := PlanAssessment(PlanInput{Config: cfg, CredentialAvailability: map[string]bool{"app\x00APPLICATION_COOKIES\x00cred-1": true}})
	if !slices.ContainsFunc(wrongKind.Capabilities, func(e assessment.CapabilityEvidence) bool {
		return e.TargetID == "app" && e.Capability == assessment.CapAuthWeb && e.State == assessment.StateUnavailable
	}) {
		t.Fatalf("credential of a different access kind was treated as available: %+v", wrongKind.Capabilities)
	}
	available := PlanAssessment(PlanInput{Config: cfg, CredentialAvailability: map[string]bool{"app\x00APPLICATION_HEADERS\x00cred-1": true}})
	if !slices.ContainsFunc(available.Capabilities, func(e assessment.CapabilityEvidence) bool {
		return e.TargetID == "app" && e.Capability == assessment.CapAuthWeb && e.State == assessment.StateAvailable
	}) {
		t.Fatalf("resolved target-bound credential not reflected: %+v", available.Capabilities)
	}
	if missing.Fingerprint == available.Fingerprint {
		t.Fatal("credential availability changes must change the plan fingerprint")
	}
	for _, decision := range available.Decisions {
		if decision.TargetID == "app" && decision.Scanner == "zap" && decision.ExecutionMode != "unauthenticated" {
			t.Fatalf("available credential was incorrectly labeled verified: %+v", decision)
		}
		if decision.TargetID == "other" && decision.ExecutionMode == "authenticated" {
			t.Fatalf("credential crossed target binding: %+v", decision)
		}
	}
}

func TestPlannerDeduplicatesScannerJobsAcrossRequestedCoverageTypes(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode:    assessment.ModeBlackBox,
		Types:   []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}},
	}
	plan := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"zap": true, "nuclei": true, "testssl": true}})
	var zapJobs []PlanJob
	for _, job := range plan.Jobs {
		if job.Scanner == "zap" {
			zapJobs = append(zapJobs, job)
		}
	}
	if len(zapJobs) != 1 || !slices.Equal(zapJobs[0].AssessmentTypes, []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}) {
		t.Fatalf("expected one ZAP job covering both requested types, got %+v", zapJobs)
	}
}

func TestUnsupportedCloudAndKubernetesTypesStayVisibleAsUnavailable(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode:  assessment.ModeWhiteBox,
		Types: []assessment.Type{assessment.TypeCloud, assessment.TypeKubernetes},
		Targets: []assessment.Target{
			{ID: "cloud", Kind: assessment.KindCloudAccount, Value: "account-123"},
			{ID: "cluster", Kind: assessment.KindKubernetesCluster, Value: "prod-cluster"},
		},
	}
	plan := PlanAssessment(PlanInput{Config: cfg})
	for i, typ := range cfg.Types {
		if plan.Coverage[i].Type != typ || plan.Coverage[i].State != "unavailable" {
			t.Fatalf("coverage for %s = %+v", typ, plan.Coverage)
		}
	}
	// Cloud is now covered by named adapters (prowler/scoutsuite) that are
	// Available=false until installed, so the gap is explained as an unavailable
	// scanner rather than a synthetic "no cloud scanner" decision.
	if !slices.ContainsFunc(plan.Decisions, func(d PlanDecision) bool {
		return (d.Scanner == "prowler" || d.Scanner == "scoutsuite") && d.TargetID == "cloud" && d.State == PlanUnavailable
	}) {
		t.Fatalf("cloud adapter gap was not explained by a cloud scanner: %+v", plan.Decisions)
	}
	if !slices.ContainsFunc(plan.Decisions, func(d PlanDecision) bool {
		return d.Scanner == "kube-bench" && d.TargetID == "cluster" && d.State == PlanUnavailable
	}) {
		t.Fatalf("kubernetes adapter gap was not explained: %+v", plan.Decisions)
	}
}

func TestPlanFingerprintBindsAvailabilityDecisionsAndConditionalJobState(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork}, Targets: []assessment.Target{{ID: "domain", Kind: assessment.KindDomain, Value: "example.test"}}, SubdomainDiscovery: true}
	available := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"subfinder": true}})
	unavailable := PlanAssessment(PlanInput{Config: cfg, Availability: map[string]bool{"subfinder": false}})
	if available.Fingerprint == unavailable.Fingerprint {
		t.Fatal("runtime availability changes must change the plan fingerprint")
	}
	foundConditional := false
	for _, job := range available.Jobs {
		if job.Scanner == "subfinder" {
			foundConditional = true
			if job.State != PlanConditional {
				t.Fatalf("subdomain preparation job state = %s", job.State)
			}
		}
	}
	if !foundConditional {
		t.Fatalf("missing conditional subfinder job: %+v", available.Jobs)
	}
}

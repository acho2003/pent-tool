package scanner

import (
	"encoding/json"
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
	for _, id := range []string{"masscan", "nikto", "lynis"} {
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
	defaultPlan := PlanAssessment(PlanInput{Config: base, Availability: map[string]bool{"nikto": true}})
	for _, d := range defaultPlan.Decisions {
		if d.Scanner == "nikto" && d.TargetID == "app" && d.State != PlanOptional {
			t.Fatalf("Nikto should remain optional by default, got %+v", d)
		}
	}

	base.ScannerSelection = assessment.ScannerSelection{Mode: "custom", Variants: []string{"nikto"}}
	selected := PlanAssessment(PlanInput{Config: base, Availability: map[string]bool{"nikto": true}})
	foundJob := false
	for _, job := range selected.Jobs {
		if job.Scanner == "nikto" && job.TargetID == "app" {
			foundJob = true
		}
	}
	if !foundJob {
		t.Fatalf("explicitly selected and available Nikto should create a planned job: %+v", selected)
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

func TestPlanJobsCarryStageAndDependencies(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork, assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "domain", Kind: assessment.KindDomain, Value: "example.test"}}, SubdomainDiscovery: true}
	plan := PlanAssessment(PlanInput{Config: cfg})
	byScanner := map[string]PlanJob{}
	for _, job := range plan.Jobs {
		if job.Stage == "" {
			t.Errorf("job %s has no stage", job.ID)
		}
		byScanner[job.Scanner] = job
	}
	want := map[string]string{"subfinder": StageDiscovery, "nmap": StageReachability, "nuclei": StageTemplates, "testssl": StageTLS, "zap": StageDAST, "openvas": StageDAST}
	for id, stage := range want {
		job, ok := byScanner[id]
		if !ok {
			t.Fatalf("missing %s job: %+v", id, plan.Jobs)
		}
		if job.Stage != stage {
			t.Errorf("%s stage = %q, want %q", id, job.Stage, stage)
		}
	}
	if len(byScanner["subfinder"].Dependencies) != 0 {
		t.Errorf("subfinder must have no prerequisites: %v", byScanner["subfinder"].Dependencies)
	}
	for _, id := range []string{"testssl"} {
		if got := byScanner[id].Dependencies; !slices.Equal(got, []string{byScanner["httpx"].ID}) {
			t.Errorf("%s dependencies = %v, want [%s]", id, got, byScanner["httpx"].ID)
		}
	}
	for _, id := range []string{"nuclei", "zap"} {
		crawlID := byScanner["katana"].ID
		if got := byScanner[id].Dependencies; !slices.Equal(got, []string{crawlID}) {
			t.Errorf("%s dependencies = %v, want [%s]", id, got, crawlID)
		}
	}
	// Network/host scanners are outside the web workflow; the ladder orders them
	// but adds no prerequisites their adapters do not consume.
	for _, id := range []string{"nmap", "openvas"} {
		if got := byScanner[id].Dependencies; len(got) != 0 {
			t.Errorf("%s dependencies = %v, want none", id, got)
		}
	}
}

func TestStageDependenciesSkipEmptyStagesAndStayTargetBound(t *testing.T) {
	jobs := []PlanJob{
		{ID: "zap:a:zap", Scanner: "zap", TargetID: "a"},
		{ID: "katana:a:katana", Scanner: "katana", TargetID: "a"},
		{ID: "httpx:a:httpx", Scanner: "httpx", TargetID: "a"},
		{ID: "testssl:a:testssl", Scanner: "testssl", TargetID: "a"},
		{ID: "nuclei:a:nuclei", Scanner: "nuclei", TargetID: "a"},
		{ID: "dalfox:a:dalfox", Scanner: "dalfox", TargetID: "a"},
		{ID: "httpx:b:httpx", Scanner: "httpx", TargetID: "b"},
		{ID: "zap:b:zap", Scanner: "zap", TargetID: "b"},
	}
	assignStages(jobs)
	got := map[string][]string{}
	for _, job := range jobs {
		got[job.ID] = job.Dependencies
	}
	want := map[string][]string{
		"httpx:a:httpx":     nil,
		"katana:a:katana":   {"httpx:a:httpx"},
		"nuclei:a:nuclei":   {"katana:a:katana"},
		"zap:a:zap":         {"katana:a:katana"},
		"dalfox:a:dalfox":   {"katana:a:katana"},
		"testssl:a:testssl": {"httpx:a:httpx"},
		"httpx:b:httpx":     nil,
		"zap:b:zap":         {"httpx:b:httpx"},
	}
	for id, deps := range want {
		if !slices.Equal(got[id], deps) {
			t.Errorf("%s dependencies = %v, want %v", id, got[id], deps)
		}
	}
}

func TestPlanJobsSortedByStageTopologyDeterministic(t *testing.T) {
	targets := []assessment.Target{{ID: "domain", Kind: assessment.KindDomain, Value: "example.test"}, {ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork, assessment.TypeWebApplication}, Targets: targets, SubdomainDiscovery: true, ScannerSelection: assessment.ScannerSelection{Mode: "custom", Variants: []string{"subfinder", "nmap", "nuclei", "zap", "testssl", "dalfox", "wapiti"}}}
	avail := map[string]bool{"dalfox": true, "wapiti": true}
	plan := PlanAssessment(PlanInput{Config: cfg, Availability: avail})
	if len(plan.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", plan.Errors)
	}
	position := map[string]int{}
	for i, job := range plan.Jobs {
		position[job.ID] = i
	}
	for i, job := range plan.Jobs {
		for _, dep := range job.Dependencies {
			if p, ok := position[dep]; !ok || p >= i {
				t.Errorf("job %s at %d depends on %s at %d (ok=%v)", job.ID, i, dep, p, ok)
			}
		}
		if i > 0 {
			prev := plan.Jobs[i-1]
			if r, pr := stageRank(job.Stage), stageRank(prev.Stage); r < pr || (r == pr && job.ID < prev.ID) {
				t.Errorf("jobs not in stage/ID order: %s(%s) after %s(%s)", job.ID, job.Stage, prev.ID, prev.Stage)
			}
		}
	}
	if position["subfinder:domain:subfinder"] > position["zap:domain:zap"] || position["nmap:domain:nmap"] > position["zap:app:zap"] {
		t.Fatalf("discovery/reachability must run before DAST: %v", position)
	}
	if position["zap:app:zap"] > position["dalfox:app:dalfox"] {
		t.Fatalf("validation must follow DAST: %v", position)
	}

	reordered := cfg
	reordered.Targets = []assessment.Target{targets[1], targets[0]}
	reordered.ScannerSelection.Variants = []string{"wapiti", "dalfox", "testssl", "zap", "nuclei", "nmap", "subfinder"}
	again := PlanAssessment(PlanInput{Config: reordered, Availability: avail})
	var a, b []string
	for _, job := range plan.Jobs {
		a = append(a, job.ID)
	}
	for _, job := range again.Jobs {
		b = append(b, job.ID)
	}
	if !slices.Equal(a, b) {
		t.Fatalf("job order depends on input order:\n%v\n%v", a, b)
	}
}

func TestPlanFingerprintBindsToolVersionsAndCredentialRevisions(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeGrayBox, Types: []assessment.Type{assessment.TypeWebApplication},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}},
		Access:  []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessBearerToken, CredentialID: "cred-1"}},
	}
	creds := map[string]bool{"app\x00BEARER_TOKEN\x00cred-1": true}
	base := PlanAssessment(PlanInput{Config: cfg, CredentialAvailability: creds, ToolVersions: map[string]string{"zap": "2.15.0"}, CredentialRevisions: map[string]string{"cred-1": "1"}})
	same := PlanAssessment(PlanInput{Config: cfg, CredentialAvailability: creds, ToolVersions: map[string]string{"zap": "2.15.0"}, CredentialRevisions: map[string]string{"cred-1": "1"}})
	if base.Fingerprint != same.Fingerprint {
		t.Fatal("identical inputs produced different fingerprints")
	}
	tool := PlanAssessment(PlanInput{Config: cfg, CredentialAvailability: creds, ToolVersions: map[string]string{"zap": "2.16.0"}, CredentialRevisions: map[string]string{"cred-1": "1"}})
	if tool.Fingerprint == base.Fingerprint {
		t.Fatal("tool version change must change the plan fingerprint")
	}
	rotated := PlanAssessment(PlanInput{Config: cfg, CredentialAvailability: creds, ToolVersions: map[string]string{"zap": "2.15.0"}, CredentialRevisions: map[string]string{"cred-1": "2"}})
	if rotated.Fingerprint == base.Fingerprint {
		t.Fatal("credential revision change must change the plan fingerprint")
	}
	// Inputs that fail validation still bind the revisions they were planned with.
	invalid := cfg
	invalid.Targets = nil
	e1 := PlanAssessment(PlanInput{Config: invalid, ToolVersions: map[string]string{"zap": "2.15.0"}})
	e2 := PlanAssessment(PlanInput{Config: invalid, ToolVersions: map[string]string{"zap": "2.16.0"}})
	if len(e1.Errors) == 0 || e1.Fingerprint == e2.Fingerprint {
		t.Fatalf("error-path fingerprint ignores tool versions: %+v", e1.Errors)
	}
	data, _ := json.Marshal(base)
	if strings.Contains(string(data), "2.15.0") || strings.Contains(string(data), "tool_versions") || strings.Contains(string(data), "credential_revisions") {
		t.Fatalf("fingerprint-only inputs leaked into the plan JSON: %s", data)
	}
}

func TestPlanFingerprintStableWithinRegistryV5WhenNewFieldsEmpty(t *testing.T) {
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	nilMaps := PlanAssessment(PlanInput{Config: cfg})
	emptyMaps := PlanAssessment(PlanInput{Config: cfg, ToolVersions: map[string]string{}, CredentialRevisions: map[string]string{}})
	if nilMaps.RegistryVersion != "5" || nilMaps.Fingerprint != emptyMaps.Fingerprint {
		t.Fatalf("empty fingerprint inputs changed the fingerprint: %q vs %q (registry %q)", nilMaps.Fingerprint, emptyMaps.Fingerprint, nilMaps.RegistryVersion)
	}
	if got := planFingerprint(nilMaps, nil, nil); got != nilMaps.Fingerprint {
		t.Fatalf("recomputed fingerprint %q != %q", got, nilMaps.Fingerprint)
	}
}

func TestRegistryVersionIsFive(t *testing.T) {
	if PlanRegistryVersion != "5" {
		t.Fatalf("PlanRegistryVersion = %q, want 5", PlanRegistryVersion)
	}
	plan := PlanAssessment(PlanInput{Config: assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork}, Targets: []assessment.Target{{ID: "h", Kind: assessment.KindIP, Value: "192.0.2.1"}}}})
	if plan.RegistryVersion != "5" {
		t.Fatalf("plan registry version = %q", plan.RegistryVersion)
	}
}

func TestDiscoveryProvidersSelectInAutoModeWithoutCustomDemotion(t *testing.T) {
	cfg := assessment.AssessmentConfig{
		Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication},
		Targets:            []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}},
		DiscoveryProviders: &assessment.DiscoveryProviders{TLS: assessment.ProviderSSLyze, Historical: assessment.ProviderWaybackurls},
	}
	plan := PlanAssessment(PlanInput{Config: cfg})
	if len(plan.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", plan.Errors)
	}
	if plan.Config.ScannerSelection.Mode != "auto" {
		t.Fatalf("provider selection switched mode to %q", plan.Config.ScannerSelection.Mode)
	}
	var testssl, sslyze, wayback *PlanDecision
	for i := range plan.Decisions {
		d := &plan.Decisions[i]
		if d.TargetID != "app" {
			continue
		}
		switch d.Scanner {
		case "testssl":
			testssl = d
		case "sslyze":
			sslyze = d
		case "waybackurls":
			wayback = d
		case "nuclei", "zap":
			if d.State != PlanSelected || d.ReasonCode == "selection.customized" {
				t.Errorf("auto-mode scanner %s demoted by provider selection: %+v", d.Scanner, d)
			}
		}
	}
	if testssl == nil || testssl.State != PlanSkipped || testssl.ReasonCode != "selection.provider_alternative" {
		t.Fatalf("testssl not skipped as provider alternative: %+v", testssl)
	}
	if sslyze == nil || sslyze.State != PlanUnavailable || wayback == nil || wayback.State != PlanUnavailable {
		t.Fatalf("unregistered chosen providers must surface as unavailable: sslyze=%+v wayback=%+v", sslyze, wayback)
	}
	for _, job := range plan.Jobs {
		if job.Scanner == "testssl" {
			t.Fatalf("testssl job planned although sslyze was chosen: %+v", job)
		}
	}
	if !slices.ContainsFunc(plan.Jobs, func(j PlanJob) bool { return j.Scanner == "zap" }) {
		t.Fatalf("auto-mode zap job missing: %+v", plan.Jobs)
	}

	cfg.DiscoveryProviders = &assessment.DiscoveryProviders{TLS: assessment.ProviderTestssl}
	explicit := PlanAssessment(PlanInput{Config: cfg})
	if !slices.ContainsFunc(explicit.Jobs, func(j PlanJob) bool { return j.Scanner == "testssl" && j.State == PlanSelected }) {
		t.Fatalf("explicit testssl provider not planned: %+v", explicit.Jobs)
	}
	if slices.ContainsFunc(explicit.Jobs, func(j PlanJob) bool { return j.Scanner == "sslyze" }) {
		t.Fatalf("unchosen TLS alternative must not run: %+v", explicit.Jobs)
	}
}

func TestProviderSelectionsMarkAlternatives(t *testing.T) {
	chosen, replaced := providerSelections(&assessment.DiscoveryProviders{Subdomain: []string{"amass"}, Historical: "waybackurls", TLS: "sslyze"})
	for _, id := range []string{"amass", "waybackurls", "sslyze"} {
		if !chosen[id] {
			t.Errorf("%s not chosen", id)
		}
	}
	if replaced["subfinder"] != "amass" || replaced["gau"] != "waybackurls" || replaced["testssl"] != "sslyze" {
		t.Fatalf("alternatives = %v", replaced)
	}
	if c, r := providerSelections(nil); len(c) != 0 || len(r) != 0 {
		t.Fatalf("nil providers selected %v / %v", c, r)
	}
}

func TestRegistryWebDefinitionsCarryStagePolicySupportAndOutputFormat(t *testing.T) {
	formats := map[string]bool{"jsonl": true, "json": true, "text": true, "xml": true}
	policies := map[string]bool{PolicyGetHeadOnly: true, PolicyExclusions: true, PolicyRateLimited: true, PolicyScopeRegex: true, PolicyWriteCapable: true, PolicyOASTDisabled: true}
	seen := 0
	for _, def := range ScannerRegistry() {
		if def.Group != GroupWebAPI {
			continue
		}
		seen++
		if def.Stage == "" || def.Stage != stageForScanner(def.ID) || stageRank(def.Stage) < 0 {
			t.Errorf("%s stage = %q", def.ID, def.Stage)
		}
		if !formats[def.OutputFormat] {
			t.Errorf("%s output format = %q", def.ID, def.OutputFormat)
		}
		if def.PolicySupport == nil || !slices.IsSorted(def.PolicySupport) {
			t.Errorf("%s policy support must be set and sorted: %v", def.ID, def.PolicySupport)
		}
		for _, p := range def.PolicySupport {
			if !policies[p] {
				t.Errorf("%s has unknown policy %q", def.ID, p)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no web/API registry entries")
	}
	if d, _ := RegistryEntry("zap"); d.Stage != StageDAST || !slices.Contains(d.PolicySupport, PolicyWriteCapable) || !slices.Contains(d.PolicySupport, PolicyExclusions) {
		t.Fatalf("zap metadata = %+v", d)
	}
	if d, _ := RegistryEntry("katana"); d.Stage != StageCrawl || d.OutputFormat != "jsonl" || !slices.Contains(d.PolicySupport, PolicyScopeRegex) {
		t.Fatalf("katana metadata = %+v", d)
	}
	data, _ := json.Marshal(ScannerDefinition{ID: "x"})
	for _, key := range []string{"\"stage\"", "policy_support", "output_format"} {
		if strings.Contains(string(data), key) {
			t.Fatalf("empty metadata must be omitted: %s", data)
		}
	}
}

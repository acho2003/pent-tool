package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"slices"
)

// ScannerRegistry is the authoritative scanner catalog. Definitions for
// adapters not implemented in this build are included with Available=false so
// the planner and UI can explain the gap without pretending the tool runs.
func ScannerRegistry() []ScannerDefinition {
	network := []assessment.Type{assessment.TypeNetwork, assessment.TypeHost}
	web := []assessment.Type{assessment.TypeWebApplication}
	api := []assessment.Type{assessment.TypeAPI}
	source := []assessment.Type{assessment.TypeSourceCode}
	defs := []ScannerDefinition{
		{ID: "subfinder", Name: "subfinder", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeNetwork, assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "conditional", Risk: "low", Available: true, Summary: "Discover approved subdomains"},
		{ID: "httpx", Name: "httpx", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeNetwork, assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindURL, assessment.KindIP, assessment.KindCIDR, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Probe approved hosts for live web services"},
		{ID: "nmap", Name: "nmap", Category: PhaseRecon, AssessmentTypes: network, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindIP, assessment.KindCIDR, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "automatic", Risk: "medium", Available: true, Summary: "Discover approved network services"},
		{ID: "katana", Name: "katana", Category: PhaseRecon, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "automatic", Risk: "low", Available: false, Summary: "Headless crawl of a web host to discover in-scope URLs and API endpoints"},
		{ID: "nuclei", Name: "nuclei", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindIP, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "automatic", Risk: "medium", Available: true, Summary: "Template-based web vulnerability checks"},
		{ID: "zap", Name: "zap", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb, assessment.CapSchema}, SupportsAuthentication: true, DefaultSelection: "automatic", Risk: "high", Available: true, Summary: "Crawl and test web applications and APIs"},
		{ID: "testssl", Name: "testssl", Category: PhaseWeb, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeNetwork}, TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindIP, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Assess TLS configuration"},
		{ID: "openvas", Name: "openvas", Category: PhaseServer, AssessmentTypes: network, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindIP, assessment.KindCIDR, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, OptionalCapabilities: []assessment.Capability{assessment.CapSSH}, DefaultSelection: "automatic", Risk: "medium", Available: true, Summary: "Run Greenbone network vulnerability checks"},
		{ID: "vuls", Name: "vuls", Category: PhaseServer, AssessmentTypes: []assessment.Type{assessment.TypeHost}, TargetKinds: []assessment.TargetKind{assessment.KindHost, assessment.KindIP, assessment.KindDomain}, RequiredCapabilities: []assessment.Capability{assessment.CapSSH}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Audit host packages using an operator-managed SSH alias"},
		{ID: "trivy", Name: "trivy", Category: PhaseSAST, AssessmentTypes: []assessment.Type{assessment.TypeSourceCode, assessment.TypeDependencies, assessment.TypeContainer, assessment.TypeIaC}, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath, assessment.KindDockerImage, assessment.KindSBOM}, RequiredCapabilities: []assessment.Capability{assessment.CapSource}, OptionalCapabilities: []assessment.Capability{assessment.CapImage, assessment.CapDependency, assessment.CapIaC, assessment.CapSBOM}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Scan source, dependencies, images, and supported IaC"},
		{ID: "semgrep", Name: "semgrep", Category: PhaseSAST, AssessmentTypes: source, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath}, RequiredCapabilities: []assessment.Capability{assessment.CapSource}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Static source-code analysis"},
		{ID: "gitleaks", Name: "gitleaks", Category: PhaseSAST, AssessmentTypes: source, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath}, RequiredCapabilities: []assessment.Capability{assessment.CapSource}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Detect secrets in repository or source files"},
		{ID: "osv", Name: "osv", Category: PhaseSAST, AssessmentTypes: []assessment.Type{assessment.TypeDependencies}, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath, assessment.KindSBOM}, RequiredCapabilities: []assessment.Capability{assessment.CapDependency}, OptionalCapabilities: []assessment.Capability{assessment.CapSBOM}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Check dependency manifests and supported SBOMs"},
		{ID: "masscan", Name: "masscan", Category: PhaseRecon, AssessmentTypes: network, TargetKinds: []assessment.TargetKind{assessment.KindIP, assessment.KindCIDR}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "Optional bounded common-port discovery at a conservative packet rate"},
		{ID: "nikto", Name: "nikto", Category: PhaseWeb, AssessmentTypes: web, TargetKinds: []assessment.TargetKind{assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "Optional root-path web server checks with bounded rate and test categories"},
		{ID: "dalfox", Name: "dalfox", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "XSS detection over discovered parameterized URLs"},
		{ID: "wapiti", Name: "wapiti", Category: PhaseWeb, AssessmentTypes: web, TargetKinds: []assessment.TargetKind{assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "Bounded web fuzzing seeded with discovered endpoints"},
		{ID: "sqlmap", Name: "sqlmap", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb, assessment.CapAPI}, SupportsAuthentication: true, DefaultSelection: "explicit_opt_in", Risk: "high", Available: false, Summary: "Opt-in, detection-only SQL injection checks on approved parameters"},
		{ID: "lynis", Name: "lynis", Category: PhaseServer, AssessmentTypes: []assessment.Type{assessment.TypeHost, assessment.TypeCompliance}, TargetKinds: []assessment.TargetKind{assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapSSH}, DefaultSelection: "automatic", Risk: "low", Available: false, Summary: "Run a bounded Lynis audit through a target-bound SSH alias"},
	}
	for i := range defs {
		defs[i].Selectable = slices.Contains(OrderedNames, defs[i].ID)
	}
	return defs
}

func RegistryEntry(id string) (ScannerDefinition, bool) {
	for _, def := range ScannerRegistry() {
		if def.ID == id {
			return def, true
		}
	}
	return ScannerDefinition{}, false
}

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
		{ID: "amass", Name: "amass", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "Gather passive subdomain candidates"},
		{ID: "dnsx", Name: "dnsx", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "automatic", Risk: "low", Available: false, Summary: "Resolve approved hostnames and record DNS evidence"},
		{ID: "gau", Name: "gau", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "Collect archived URL candidates"},
		{ID: "waybackurls", Name: "waybackurls", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "Collect Wayback URL candidates"},
		{ID: "httpx", Name: "httpx", Category: PhaseRecon, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindURL, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Probe approved origins for live web services"},
		{ID: "nmap", Name: "nmap", Category: PhaseRecon, AssessmentTypes: network, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindIP, assessment.KindCIDR, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "automatic", Risk: "medium", Available: true, Summary: "Discover approved network services"},
		{ID: "katana", Name: "katana", Category: PhaseRecon, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "automatic", Risk: "low", Available: false, Summary: "Headless crawl of a web host to discover in-scope URLs and API endpoints"},
		{ID: "nuclei", Name: "nuclei", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindIP, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "automatic", Risk: "medium", Available: true, Summary: "Template-based web vulnerability checks"},
		{ID: "zap", Name: "zap", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb, assessment.CapSchema}, SupportsAuthentication: true, DefaultSelection: "automatic", Risk: "high", Available: true, Summary: "Crawl and test web applications and APIs"},
		{ID: "apichecks", Name: "Native API checks", Category: PhaseWeb, AssessmentTypes: api, TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Check declared authentication and credentialed CORS on eligible API operations"},
		{ID: "testssl", Name: "testssl", Category: PhaseWeb, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeNetwork}, TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindIP, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Assess TLS configuration"},
		{ID: "sslyze", Name: "sslyze", Category: PhaseWeb, AssessmentTypes: []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI}, TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindDomain, assessment.KindIP, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "Assess an approved TLS service"},
		{ID: "openvas", Name: "openvas", Category: PhaseServer, AssessmentTypes: network, TargetKinds: []assessment.TargetKind{assessment.KindDomain, assessment.KindIP, assessment.KindCIDR, assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, OptionalCapabilities: []assessment.Capability{assessment.CapSSH}, DefaultSelection: "automatic", Risk: "medium", Available: true, Summary: "Run Greenbone network vulnerability checks"},
		{ID: "vuls", Name: "vuls", Category: PhaseServer, AssessmentTypes: []assessment.Type{assessment.TypeHost}, TargetKinds: []assessment.TargetKind{assessment.KindHost, assessment.KindIP, assessment.KindDomain}, RequiredCapabilities: []assessment.Capability{assessment.CapSSH}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Audit host packages using an operator-managed SSH alias"},
		{ID: "trivy", Name: "trivy", Category: PhaseSAST, AssessmentTypes: []assessment.Type{assessment.TypeSourceCode, assessment.TypeDependencies, assessment.TypeContainer, assessment.TypeIaC}, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath, assessment.KindDockerImage, assessment.KindSBOM}, RequiredCapabilities: []assessment.Capability{assessment.CapSource}, OptionalCapabilities: []assessment.Capability{assessment.CapImage, assessment.CapDependency, assessment.CapIaC, assessment.CapSBOM}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Scan source, dependencies, images, and supported IaC"},
		{ID: "semgrep", Name: "semgrep", Category: PhaseSAST, AssessmentTypes: source, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath}, RequiredCapabilities: []assessment.Capability{assessment.CapSource}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Static source-code analysis"},
		{ID: "gitleaks", Name: "gitleaks", Category: PhaseSAST, AssessmentTypes: source, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath}, RequiredCapabilities: []assessment.Capability{assessment.CapSource}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Detect secrets in repository or source files"},
		{ID: "osv", Name: "osv", Category: PhaseSAST, AssessmentTypes: []assessment.Type{assessment.TypeDependencies}, TargetKinds: []assessment.TargetKind{assessment.KindRepository, assessment.KindLocalSourcePath, assessment.KindSBOM}, RequiredCapabilities: []assessment.Capability{assessment.CapDependency}, OptionalCapabilities: []assessment.Capability{assessment.CapSBOM}, DefaultSelection: "automatic", Risk: "low", Available: true, Summary: "Check dependency manifests and supported SBOMs"},
		{ID: "masscan", Name: "masscan", Category: PhaseRecon, AssessmentTypes: network, TargetKinds: []assessment.TargetKind{assessment.KindIP, assessment.KindCIDR}, RequiredCapabilities: []assessment.Capability{assessment.CapNetwork}, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "Optional bounded common-port discovery at a conservative packet rate"},
		{ID: "nikto", Name: "nikto", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), network...), TargetKinds: []assessment.TargetKind{assessment.KindURL, assessment.KindIP, assessment.KindHost, assessment.KindDomain}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "Optional root-path web server checks on a URL or network host"},
		{ID: "dalfox", Name: "dalfox", Category: PhaseWeb, AssessmentTypes: append(append([]assessment.Type{}, web...), api...), TargetKinds: []assessment.TargetKind{assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "XSS detection over discovered parameterized URLs"},
		{ID: "wapiti", Name: "wapiti", Category: PhaseWeb, AssessmentTypes: web, TargetKinds: []assessment.TargetKind{assessment.KindURL}, RequiredCapabilities: []assessment.Capability{assessment.CapWeb}, OptionalCapabilities: []assessment.Capability{assessment.CapAuthWeb}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "medium", Available: false, Summary: "Bounded web fuzzing seeded with discovered endpoints"},
		{ID: "lynis", Name: "lynis", Category: PhaseServer, AssessmentTypes: []assessment.Type{assessment.TypeHost, assessment.TypeCompliance}, TargetKinds: []assessment.TargetKind{assessment.KindHost}, RequiredCapabilities: []assessment.Capability{assessment.CapSSH}, DefaultSelection: "automatic", Risk: "low", Available: false, Summary: "Run a bounded Lynis audit through a target-bound SSH alias"},
		{ID: "prowler", Name: "prowler", Category: PhaseCloud, AssessmentTypes: []assessment.Type{assessment.TypeCloud, assessment.TypeCompliance}, TargetKinds: []assessment.TargetKind{assessment.KindCloudAccount}, RequiredCapabilities: []assessment.Capability{assessment.CapCloud}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "Read-only AWS security & configuration audit using a supplied read-only credential"},
		{ID: "scoutsuite", Name: "scoutsuite", Category: PhaseCloud, AssessmentTypes: []assessment.Type{assessment.TypeCloud, assessment.TypeCompliance}, TargetKinds: []assessment.TargetKind{assessment.KindCloudAccount}, RequiredCapabilities: []assessment.Capability{assessment.CapCloud}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "Read-only multi-cloud security posture audit using a supplied read-only credential"},
		{ID: "kube-bench", Name: "kube-bench", Category: PhaseKubernetes, AssessmentTypes: []assessment.Type{assessment.TypeKubernetes, assessment.TypeCompliance}, TargetKinds: []assessment.TargetKind{assessment.KindKubernetesCluster}, RequiredCapabilities: []assessment.Capability{assessment.CapKubernetes}, SupportsAuthentication: true, DefaultSelection: "optional", Risk: "low", Available: false, Summary: "CIS Kubernetes benchmark checks against a supplied kubeconfig"},
	}
	for i := range defs {
		defs[i].Selectable = slices.Contains(OrderedNames, defs[i].ID)
		defs[i].Group = scannerGroups[defs[i].ID]
		if defs[i].Group == GroupWebAPI {
			meta := webScannerMetadata[defs[i].ID]
			defs[i].Stage = stageForScanner(defs[i].ID)
			defs[i].PolicySupport = append([]string{}, meta.policy...)
			defs[i].OutputFormat = meta.format
		}
	}
	return defs
}

// webScannerMetadata records, for each web/API adapter, the policy controls it
// can enforce or must be gated on and the output format it parses. Policy
// lists are sorted. Exclusions and scope are also enforced by the dispatcher;
// these describe what the tool honours itself.
var webScannerMetadata = map[string]struct {
	policy []string
	format string
}{
	"subfinder":   {[]string{PolicyRateLimited}, "jsonl"},
	"amass":       {[]string{PolicyRateLimited}, "text"},
	"dnsx":        {[]string{PolicyRateLimited}, "jsonl"},
	"gau":         {[]string{}, "text"},
	"waybackurls": {[]string{}, "text"},
	"sslyze":      {[]string{PolicyGetHeadOnly}, "json"},
	"httpx":       {[]string{PolicyGetHeadOnly, PolicyRateLimited}, "jsonl"},
	"katana":      {[]string{PolicyExclusions, PolicyRateLimited, PolicyScopeRegex}, "jsonl"},
	"nuclei":      {[]string{PolicyOASTDisabled, PolicyRateLimited, PolicyWriteCapable}, "jsonl"},
	"zap":         {[]string{PolicyExclusions, PolicyScopeRegex, PolicyWriteCapable}, "json"},
	"apichecks":   {[]string{PolicyExclusions, PolicyGetHeadOnly, PolicyRateLimited, PolicyScopeRegex}, "jsonl"},
	"testssl":     {[]string{PolicyGetHeadOnly}, "json"},
	"nikto":       {[]string{PolicyRateLimited}, "json"},
	"dalfox":      {[]string{PolicyOASTDisabled, PolicyRateLimited, PolicyWriteCapable}, "json"},
	"wapiti":      {[]string{PolicyExclusions, PolicyWriteCapable}, "json"},
}

// scannerGroups assigns each scanner to a New-Assessment UI group. Recon/web
// tools group under Web & API; nmap/masscan/openvas/vuls/lynis under Network &
// servers; SAST/dependency/container tools under Code; and the cloud/k8s audit
// adapters under their respective groups.
var scannerGroups = map[string]string{
	"auth":      GroupWebAPI,
	"subfinder": GroupWebAPI, "amass": GroupWebAPI, "dnsx": GroupWebAPI, "gau": GroupWebAPI, "waybackurls": GroupWebAPI, "sslyze": GroupWebAPI, "httpx": GroupWebAPI, "katana": GroupWebAPI,
	"nuclei": GroupWebAPI, "zap": GroupWebAPI, "apichecks": GroupWebAPI, "apiwrites": GroupWebAPI, "testssl": GroupWebAPI,
	"nikto": GroupWebAPI, "dalfox": GroupWebAPI, "wapiti": GroupWebAPI,
	"nmap": GroupNetwork, "masscan": GroupNetwork, "openvas": GroupNetwork,
	"vuls": GroupNetwork, "lynis": GroupNetwork,
	"trivy": GroupCode, "semgrep": GroupCode, "gitleaks": GroupCode, "osv": GroupCode,
	"prowler": GroupCloud, "scoutsuite": GroupCloud,
	"kube-bench": GroupKubernetes,
}

func RegistryEntry(id string) (ScannerDefinition, bool) {
	for _, def := range ScannerRegistry() {
		if def.ID == id {
			return def, true
		}
	}
	return ScannerDefinition{}, false
}

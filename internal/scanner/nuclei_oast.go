package scanner

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// NucleiOASTVariant is the separately consented Nuclei job that runs only
// out-of-band (OAST) templates against the operator's own Interactsh server.
// The ordinary Nuclei job keeps interactsh disabled (-ni) and OAST templates
// excluded; this variant inherits every other Nuclei safeguard (gateway,
// excluded tags, rate, signed templates, scope) because it is the same scanner.
const NucleiOASTVariant = "nuclei-oast"

// nucleiOASTTags are the template tags that need a callback server. They are
// excluded from ordinary Nuclei runs and selected by the OAST variant.
var nucleiOASTTags = []string{"oast", "oob", "interactsh"}

// publicInteractshHosts are ProjectDiscovery's public callback servers, which
// Nuclei uses by default. Payloads naming the target would be sent to them, so
// Xalgorix never uses them: only an operator-run server is accepted.
var publicInteractshHosts = []string{"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "interact.sh", "interactsh.com"}

// InteractshUnavailableReason validates the configured self-hosted Interactsh
// server URL, or explains why OAST testing cannot be planned.
func InteractshUnavailableReason(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return "out-of-band testing needs a self-hosted Interactsh server; set XALGORIX_INTERACTSH_SERVER"
	}
	parsed, err := url.Parse(server)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "XALGORIX_INTERACTSH_SERVER must be an http(s) origin such as https://oast.example.org"
	}
	host := strings.ToLower(parsed.Hostname())
	for _, public := range publicInteractshHosts {
		if host == public || strings.HasSuffix(host, "."+public) {
			return "XALGORIX_INTERACTSH_SERVER names a public Interactsh service; out-of-band payloads would disclose targets to a third party, so only a self-hosted server is accepted"
		}
	}
	return ""
}

// nucleiOASTArgs turns the reviewed Nuclei policy into the OAST variant:
// interactsh is enabled against the configured server only, the OAST tags are
// selected instead of excluded, and every other excluded tag stays excluded.
func nucleiOASTArgs(args []string, server, token string) ([]string, error) {
	if reason := InteractshUnavailableReason(server); reason != "" {
		return nil, fmt.Errorf("%s", reason)
	}
	out := make([]string, 0, len(args)+8)
	replacedNI, replacedTags := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-ni":
			replacedNI = true
			out = append(out, "-iserver", strings.TrimSuffix(strings.TrimSpace(server), "/"))
			if strings.TrimSpace(token) != "" {
				out = append(out, "-itoken", strings.TrimSpace(token))
			}
			// Poll long enough after the last request for slow callbacks.
			out = append(out, "-interactions-cooldown-period", "20")
		case "-etags":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("nuclei policy has no excluded tag list")
			}
			i++
			var kept []string
			for _, tag := range strings.Split(args[i], ",") {
				if !slices.Contains(nucleiOASTTags, tag) {
					kept = append(kept, tag)
				}
			}
			replacedTags = true
			out = append(out, "-etags", strings.Join(kept, ","), "-tags", strings.Join(nucleiOASTTags, ","))
		default:
			out = append(out, args[i])
		}
	}
	if !replacedNI || !replacedTags {
		return nil, fmt.Errorf("nuclei policy flags changed; the OAST variant cannot be derived safely")
	}
	return out, nil
}

// appendOASTJobs adds, only with explicit consent, one OAST variant per target
// whose ordinary Nuclei job is selected. Availability ("nuclei-oast") requires
// Nuclei and a valid self-hosted Interactsh server; otherwise the job is
// planned as unavailable with the reason, so consent never silently vanishes.
func appendOASTJobs(plan *AssessmentPlan, cfg assessment.AssessmentConfig, availability map[string]bool, reasons map[string]string) {
	if !cfg.OASTCallbacks {
		return
	}
	if cfg.WorkflowVersion != "unified-v1" {
		plan.Warnings = append(plan.Warnings, assessment.Problem{Code: "oast.workflow_required", Message: "Out-of-band callback testing runs only in the unified workflow; it was not planned."})
		return
	}
	added := false
	for _, job := range slices.Clone(plan.Jobs) {
		if job.Scanner != "nuclei" || job.Variant != "nuclei" || job.State != PlanSelected || job.AuthContextID != "" {
			continue
		}
		oast := job
		oast.ID = "nuclei-oast:" + job.TargetID
		oast.Variant = NucleiOASTVariant
		oast.Reason = "Explicitly consented out-of-band templates against the deployment's self-hosted Interactsh server"
		if available, known := availability[NucleiOASTVariant]; known && !available {
			oast.State = PlanUnavailable
			oast.Reason = firstNonEmpty(reasons[NucleiOASTVariant], InteractshUnavailableReason(""))
		}
		plan.Jobs = append(plan.Jobs, oast)
		plan.Decisions = append(plan.Decisions, PlanDecision{Scanner: "nuclei", TargetID: job.TargetID, Types: job.AssessmentTypes, State: oast.State, ReasonCode: "oast.explicit_consent", Reason: oast.Reason})
		added = true
	}
	if !added {
		plan.Warnings = append(plan.Warnings, assessment.Problem{Code: "oast.nuclei_required", Message: "Out-of-band callback testing needs a selected Nuclei job; none was planned."})
	}
}

// nucleiOASTLimitations records what the OAST variant does and does not cover.
func nucleiOASTLimitations() []RunLimitation {
	var excluded []string
	for _, tag := range nucleiExcludedTags {
		if !slices.Contains(nucleiOASTTags, tag) {
			excluded = append(excluded, tag)
		}
	}
	return []RunLimitation{
		{Kind: string(GapExcluded), Reason: "nuclei OAST variant ran only callback templates (tags " + strings.Join(nucleiOASTTags, ", ") + "); still excluded: " + strings.Join(excluded, ", ") + "; headless templates were not run"},
		{Kind: "callback_window", Reason: "callbacks are matched only while Nuclei polls the self-hosted Interactsh server; a target that calls back later, or cannot reach that server, produces no result"},
	}
}

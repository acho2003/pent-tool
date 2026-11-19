package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/acho2003/pent-tool/internal/assessment"
	"github.com/acho2003/pent-tool/internal/config"
	"github.com/acho2003/pent-tool/internal/credentials"
	"github.com/acho2003/pent-tool/internal/scanner"
	"github.com/acho2003/pent-tool/internal/scopeguard"
	"github.com/acho2003/pent-tool/internal/web"
)

type assessmentCLIResult struct {
	State       string                 `json:"state"`
	Plan        scanner.AssessmentPlan `json:"plan"`
	Runs        []scanner.Run          `json:"scanner_runs"`
	Findings    []scanner.Finding      `json:"findings"`
	ParseErrors []string               `json:"parse_errors,omitempty"`
}

func runAssessmentCLI(args cliArgs) error {
	return executeAssessmentCLI(args, config.Get(), os.Stdout)
}

func executeAssessmentCLI(args cliArgs, appConfig *config.Config, output io.Writer) error {
	if appConfig == nil {
		return errors.New("application configuration is required")
	}
	if output == nil {
		return errors.New("assessment output writer is required")
	}
	if len(args.headers) > 0 {
		return errors.New("raw --header values are not supported for typed CLI assessments; configure target-bound credentials through the web UI")
	}
	assessmentConfig, err := assessmentConfigFromCLI(args)
	if err != nil {
		return err
	}
	if sharedTokenRequested(args) && headerAuthRequested(args) {
		return errors.New("--system-template and --auth-header-file cannot be combined; choose one authentication source")
	}
	var transientVault *credentials.Vault
	switch {
	case sharedTokenRequested(args):
		// The CLI mints the access bindings itself from --shared-token-file and
		// stages the token in a transient in-memory vault, so the generic
		// "cannot resolve credential references" refusal below does not apply.
		transientVault, err = expandSystemTemplateIntoConfig(&assessmentConfig, args)
	case headerAuthRequested(args):
		// --auth-header-file binds a cookie/bearer credential to the --target(s)
		// with the same transient-vault plumbing, keeping whole-origin scope.
		transientVault, err = applyHeaderFileAuthToConfig(&assessmentConfig, args)
	}
	if err != nil {
		return err
	}
	if len(assessmentConfig.Access) > 0 && !cliAuthRequested(args) {
		return errors.New("typed CLI execution cannot resolve credential references; remove access bindings and use the authenticated web UI, or supply --system-template/--shared-token-file or --auth-header-file")
	}
	for _, target := range assessmentConfig.Targets {
		switch target.Kind {
		case assessment.KindDomain, assessment.KindURL, assessment.KindIP, assessment.KindCIDR, assessment.KindHost:
			if scopeguard.IsLocalOrListener(scopeguard.Config{BindAddr: appConfig.BindAddr, AllowLocalTargets: appConfig.AllowLocalTargets}, target.Value) {
				return fmt.Errorf("target %q is local or points at the 21Pent host; CLI assessment refused by local-target policy", target.Value)
			}
		}
	}

	scanConfig := web.ScannerConfig(appConfig)
	scanConfig.WebProfile = assessmentConfig.Profile
	plan, err := cliAssessmentPlanFromConfig(args, assessmentConfig, appConfig)
	if err != nil {
		return err
	}
	if len(plan.Errors) > 0 {
		return fmt.Errorf("assessment plan has %d blocking validation error(s)", len(plan.Errors))
	}
	selected := false
	for _, job := range plan.Jobs {
		if job.State == scanner.PlanSelected {
			selected = true
			break
		}
	}
	if !selected {
		return errors.New("assessment plan has no runnable selected jobs")
	}
	if appConfig.DataDir == "" {
		return errors.New("21Pent data directory is not configured")
	}
	assessmentRoot := filepath.Join(appConfig.DataDir, "assessments")
	if err := os.MkdirAll(assessmentRoot, 0o700); err != nil {
		return fmt.Errorf("create assessment artifact directory: %w", err)
	}
	scanDir, err := os.MkdirTemp(assessmentRoot, time.Now().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return fmt.Errorf("create isolated assessment directory: %w", err)
	}

	pipeline := scanner.NewPipeline(scanConfig)
	if transientVault != nil {
		authHeaders, authErr := web.PrepareHeadlessAuth(context.Background(), transientVault, &plan)
		if authErr != nil {
			return fmt.Errorf("prepare shared-token authentication: %w", authErr)
		}
		pipeline.Config.AssessmentAuthHeaders = authHeaders
		pipeline.Config.AssessmentAuthContexts = plan.AuthContexts
		if os.Getenv("XALGORIX_UNIFIED_WORKFLOW") != "1" {
			fmt.Fprintln(os.Stderr, "notice: XALGORIX_UNIFIED_WORKFLOW is not \"1\"; services will be scanned authenticated but per-service OpenAPI auto-discovery will not run")
		}
	}
	runs := pipeline.RunAssessmentJobs(context.Background(), plan, scanDir, nil, nil)
	findings, parseErrors := scanner.ParseRuns(runs)
	result := assessmentCLIResult{State: assessmentRunsState(runs, parseErrors), Plan: plan, Runs: runs, Findings: findings}
	for _, parseErr := range parseErrors {
		result.ParseErrors = append(result.ParseErrors, parseErr.Error())
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write assessment result: %w", err)
	}
	return nil
}

func cliAssessmentAvailability(cfg scanner.Config) map[string]bool {
	paths := map[string]string{
		"nuclei": cfg.NucleiPath, "zap": "", "testssl": cfg.TestsslPath, "sslyze": cfg.SSLyzePath, "openvas": "",
		"vuls": cfg.VulsPath, "trivy": cfg.TrivyPath, "semgrep": cfg.SemgrepPath, "bearer": cfg.BearerPath, "nextjs-sast": cfg.SemgrepPath, "nestjs-sast": cfg.SemgrepPath,
		"gitleaks": cfg.GitleaksPath, "osv": cfg.OsvPath, "masscan": cfg.MasscanPath, "nikto": cfg.NiktoPath,
		"lynis":     cfg.SSHPath,
		"subfinder": cfg.SubfinderPath, "amass": cfg.AmassPath, "dnsx": cfg.DNSXPath, "httpx": cfg.HttpxPath, "nmap": cfg.NmapPath,
		// Staged web-pipeline adapters: availability is genuine binary presence,
		// matching the web server's scannerAvailability so a CLI assessment plans
		// the same optional web/API scanners the dashboard does.
		"katana": cfg.KatanaPath, "dalfox": cfg.DalfoxPath, "wapiti": cfg.WapitiPath, "schemathesis": cfg.SchemathesisPath,
		// Cloud / Kubernetes posture-audit adapters.
		"kube-bench": cfg.KubeBenchPath, "prowler": cfg.ProwlerPath, "scoutsuite": cfg.ScoutSuitePath,
	}
	available := make(map[string]bool, len(paths))
	for id, path := range paths {
		if id == "zap" {
			available[id] = strings.TrimSpace(cfg.ZAPURL) != "" && cfg.ZAPDedicated
			continue
		}
		if id == "openvas" {
			available[id] = (cfg.GVMHost != "" || cfg.GVMSocket != "") && cfg.GVMUser != "" && cfg.GVMPass != ""
			continue
		}
		available[id] = path != "" && commandExists(path)
	}
	if scanner.MasscanCapabilityReason() != "" {
		available["masscan"] = false
	}
	for id, ok := range scanner.IntelAvailability() {
		available[id] = ok
	}
	return available
}

func assessmentRunsState(runs []scanner.Run, parseErrors []error) string {
	completed, failed := 0, 0
	for _, run := range runs {
		switch run.Status {
		case "completed":
			completed++
		case "failed", "cancelled":
			failed++
		}
	}
	if completed == len(runs) && failed == 0 && len(parseErrors) == 0 {
		return "complete"
	}
	if completed == 0 && failed > 0 {
		return "failed"
	}
	return "partial"
}

func commandExists(path string) bool {
	_, err := exec.LookPath(path)
	return err == nil
}

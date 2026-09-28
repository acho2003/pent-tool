package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

const maxAssessmentConfigBytes = 1 << 20

func runAssessmentPlanCLI(args cliArgs) error {
	var cfg assessment.AssessmentConfig
	if args.assessmentConfig != "" {
		f, err := os.Open(args.assessmentConfig)
		if err != nil {
			return fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxAssessmentConfigBytes+1))
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}
		if len(data) > maxAssessmentConfigBytes {
			return fmt.Errorf("assessment config exceeds %d bytes", maxAssessmentConfigBytes)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("decode config: %w", err)
		}
	}
	if args.assessmentMode != "" {
		cfg.Mode = assessment.Mode(args.assessmentMode)
	}
	for _, typ := range args.assessmentTypes {
		for _, value := range strings.Split(typ, ",") {
			cfg.Types = append(cfg.Types, assessment.Type(value))
		}
	}
	if len(args.targets) > 0 {
		if len(cfg.Targets) > 0 {
			return errors.New("--target conflicts with assessment_targets in the config file")
		}
		for i, target := range args.targets {
			cfg.Targets = append(cfg.Targets, assessment.Target{ID: fmt.Sprintf("target-%d", i+1), Kind: inferAssessmentTargetKind(target), Value: target})
		}
	}
	if args.source != "" {
		if len(cfg.Targets) > 0 {
			return errors.New("--source conflicts with assessment_targets in the config file")
		}
		kind := assessment.KindLocalSourcePath
		if strings.Contains(args.source, "://") {
			kind = assessment.KindRepository
		}
		cfg.Targets = append(cfg.Targets, assessment.Target{ID: "source", Kind: kind, Value: args.source})
		if len(cfg.Types) == 0 {
			cfg.Types = []assessment.Type{assessment.TypeSourceCode, assessment.TypeDependencies}
		}
	}

	availability := map[string]bool{}
	for id, binary := range map[string]string{
		"subfinder": "subfinder", "httpx": "httpx", "nmap": "nmap", "nuclei": "nuclei",
		"testssl": "testssl.sh", "vuls": "vuls", "trivy": "trivy", "semgrep": "semgrep",
		"gitleaks": "gitleaks", "osv": "osv-scanner",
	} {
		_, err := exec.LookPath(binary)
		availability[id] = err == nil
	}
	plan := scanner.PlanAssessment(scanner.PlanInput{Config: cfg, Availability: availability})
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	if len(plan.Errors) > 0 {
		return fmt.Errorf("plan has %d blocking validation error(s)", len(plan.Errors))
	}
	return nil
}

func inferAssessmentTargetKind(raw string) assessment.TargetKind {
	value := strings.TrimSpace(raw)
	if parsed, err := url.Parse(value); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		return assessment.KindURL
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return assessment.KindCIDR
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return assessment.KindIP
	}
	return assessment.KindDomain
}

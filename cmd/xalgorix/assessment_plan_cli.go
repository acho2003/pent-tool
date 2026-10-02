package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

const maxAssessmentConfigBytes = 1 << 20

func runAssessmentPlanCLI(args cliArgs) error {
	plan, err := cliAssessmentPlan(args, config.Get())
	if err != nil {
		return err
	}
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

func assessmentConfigFromCLI(args cliArgs) (assessment.AssessmentConfig, error) {
	var cfg assessment.AssessmentConfig
	if args.assessmentConfig != "" {
		f, err := os.Open(args.assessmentConfig)
		if err != nil {
			return cfg, fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxAssessmentConfigBytes+1))
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		if len(data) > maxAssessmentConfigBytes {
			return cfg, fmt.Errorf("assessment config exceeds %d bytes", maxAssessmentConfigBytes)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("decode config: %w", err)
		}
	}
	if args.assessmentMode != "" {
		cfg.Mode = assessment.Mode(args.assessmentMode)
	}
	if args.vulsSSHHost != "" {
		return cfg, errors.New("--vuls-ssh-host is not supported by typed assessment execution; use a target-bound access resource when the remote host adapter is available")
	}
	if len(args.scanners) > 0 {
		if cfg.ScannerSelection.Mode != "" || len(cfg.ScannerSelection.Variants) > 0 {
			return cfg, errors.New("--scanners conflicts with scanner_selection in the assessment config")
		}
		selected := map[string]bool{}
		for _, raw := range args.scanners {
			id := strings.ToLower(strings.TrimSpace(raw))
			if id == "" {
				continue
			}
			if _, ok := scanner.RegistryEntry(id); !ok {
				return cfg, fmt.Errorf("unknown typed scanner variant %q", raw)
			}
			selected[id] = true
		}
		if len(selected) == 0 {
			return cfg, errors.New("--scanners requires at least one scanner variant")
		}
		cfg.ScannerSelection.Mode = "custom"
		for _, def := range scanner.ScannerRegistry() {
			if selected[def.ID] {
				cfg.ScannerSelection.Variants = append(cfg.ScannerSelection.Variants, def.ID)
			}
		}
	}
	for _, typ := range args.assessmentTypes {
		for _, value := range strings.Split(typ, ",") {
			cfg.Types = append(cfg.Types, assessment.Type(value))
		}
	}
	if len(args.targets) > 0 {
		if len(cfg.Targets) > 0 {
			return cfg, errors.New("--target conflicts with assessment_targets in the config file")
		}
		for i, target := range args.targets {
			cfg.Targets = append(cfg.Targets, assessment.Target{ID: fmt.Sprintf("target-%d", i+1), Kind: inferAssessmentTargetKind(target), Value: target})
		}
	}
	if args.source != "" {
		if len(cfg.Targets) > 0 {
			return cfg, errors.New("--source conflicts with assessment_targets in the config file")
		}
		kind := assessment.KindLocalSourcePath
		switch strings.ToLower(strings.TrimSpace(args.artifactKind)) {
		case "", "none":
			if strings.Contains(args.source, "://") {
				kind = assessment.KindRepository
			}
		case "filesystem":
			kind = assessment.KindLocalSourcePath
		case "repository":
			kind = assessment.KindRepository
		case "image":
			kind = assessment.KindDockerImage
		case "sbom":
			kind = assessment.KindSBOM
		default:
			return cfg, fmt.Errorf("unsupported typed artifact kind %q", args.artifactKind)
		}
		cfg.Targets = append(cfg.Targets, assessment.Target{ID: "source", Kind: kind, Value: args.source})
		if len(cfg.Types) == 0 {
			switch kind {
			case assessment.KindDockerImage:
				cfg.Types = []assessment.Type{assessment.TypeContainer}
			case assessment.KindSBOM:
				cfg.Types = []assessment.Type{assessment.TypeDependencies}
			default:
				cfg.Types = []assessment.Type{assessment.TypeSourceCode, assessment.TypeDependencies}
			}
		}
	} else if args.artifactKind != "" && args.artifactKind != "none" {
		return cfg, errors.New("--artifact-kind requires --source for typed assessments")
	}
	if cfg.Profile == "" {
		cfg.Profile = scanner.ProfileGentle
	}

	return cfg, nil
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

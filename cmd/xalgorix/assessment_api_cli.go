package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
	"github.com/xalgord/xalgorix/v4/internal/web"
)

const maxCLIAPIDefinitions = 16

// cliAssessmentPlan binds local specification files to explicit URL targets.
// The content hash enters the normal plan fingerprint; the file contents are
// never copied into the CLI result or treated as a source of scan targets.
func cliAssessmentPlan(args cliArgs, appConfig *config.Config) (scanner.AssessmentPlan, error) {
	var empty scanner.AssessmentPlan
	if appConfig == nil {
		return empty, errors.New("application configuration is required")
	}
	cfg, err := assessmentConfigFromCLI(args)
	if err != nil {
		return empty, err
	}
	return cliAssessmentPlanFromConfig(args, cfg, appConfig)
}

func cliAssessmentPlanFromConfig(args cliArgs, cfg assessment.AssessmentConfig, appConfig *config.Config) (scanner.AssessmentPlan, error) {
	var empty scanner.AssessmentPlan
	if len(cfg.APIDefinitions) > 0 || len(cfg.APIDefinitionIDs) > 0 {
		return empty, errors.New("typed CLI cannot resolve server-managed API definition IDs; use --api-definition target-id=file")
	}
	if len(args.apiDefinitionFiles) > maxCLIAPIDefinitions {
		return empty, fmt.Errorf("at most %d local API definitions are supported", maxCLIAPIDefinitions)
	}
	endpoints := make([]scanner.APIEndpoint, 0)
	seen := map[string]bool{}
	for _, binding := range args.apiDefinitionFiles {
		targetID, path, ok := strings.Cut(binding, "=")
		targetID, path = strings.TrimSpace(targetID), strings.TrimSpace(path)
		if !ok || targetID == "" || path == "" {
			return empty, fmt.Errorf("--api-definition must use target-id=file")
		}
		var target *assessment.Target
		for i := range cfg.Targets {
			if cfg.Targets[i].ID == targetID {
				target = &cfg.Targets[i]
				break
			}
		}
		if target == nil || target.Kind != assessment.KindURL {
			return empty, fmt.Errorf("API definition target %q must identify an explicit HTTP(S) URL target", targetID)
		}
		f, err := os.Open(path)
		if err != nil {
			return empty, fmt.Errorf("open API definition for %q: %w", targetID, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, scanner.MaxOpenAPISpecBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return empty, fmt.Errorf("read API definition for %q: %w", targetID, readErr)
		}
		if closeErr != nil {
			return empty, fmt.Errorf("close API definition for %q: %w", targetID, closeErr)
		}
		if len(data) > scanner.MaxOpenAPISpecBytes {
			return empty, fmt.Errorf("API definition for %q exceeds %d bytes", targetID, scanner.MaxOpenAPISpecBytes)
		}
		parsed, err := scanner.ParseOpenAPI(data, target.Value)
		if err != nil {
			return empty, fmt.Errorf("API definition for %q: %w", targetID, err)
		}
		hash := sha256.Sum256(data)
		id := hex.EncodeToString(hash[:])
		key := targetID + "\x00" + id
		if seen[key] {
			return empty, fmt.Errorf("duplicate API definition for target %q", targetID)
		}
		seen[key] = true
		cfg.APIDefinitions = append(cfg.APIDefinitions, assessment.APIDefinitionBinding{TargetID: targetID, DefinitionID: id})
		for i := range parsed {
			parsed[i].TargetID = targetID
		}
		endpoints = append(endpoints, parsed...)
	}
	unavailableReasons := map[string]string{}
	if commandExists(appConfig.MasscanPath) {
		if reason := scanner.MasscanCapabilityReason(); reason != "" {
			unavailableReasons["masscan"] = reason
		}
	}
	plan := scanner.PlanAssessment(scanner.PlanInput{Config: cfg, Availability: cliAssessmentAvailability(web.ScannerConfig(appConfig)), UnavailabilityReasons: unavailableReasons})
	if len(plan.Errors) == 0 {
		plan.APIEndpoints = endpoints
	}
	return plan, nil
}

package web

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func legacyFindingToScanner(v VulnSummary) scanner.Finding {
	return scanner.Finding{SourceID: v.ID, Scanner: firstFindingScanner(v), Title: v.Title, Severity: v.Severity, Target: v.Target, Endpoint: v.Endpoint, Method: v.Method, Parameter: v.Parameter, Description: v.Description, Evidence: v.TechnicalAnalysis, Remediation: v.Remediation, CVE: v.CVE, CWE: v.CWE, CVSS: v.CVSS, Scope: v.Scope, Fingerprint: v.Fingerprint}
}

func firstFindingScanner(v VulnSummary) string {
	if len(v.Scanners) > 0 && strings.TrimSpace(v.Scanners[0]) != "" {
		return v.Scanners[0]
	}
	if v.VerificationMethod != "" {
		return v.VerificationMethod
	}
	return "legacy"
}

func securityFindingToSummary(f scanner.SecurityFinding) VulnSummary {
	return VulnSummary{ID: f.ID, Fingerprint: f.Fingerprint, NormalizedType: f.NormalizedType, DedupeScope: string(f.DedupeScope), Title: f.Title, Severity: f.Severity, Status: string(f.Status), StatusReason: f.StatusReason, Target: f.Target, Scope: f.Scope, Endpoint: firstFindingEndpoint(f), CVSS: f.CVSS, CVE: strings.Join(f.CVE, ", "), CWE: strings.Join(f.CWE, ", "), Scanners: append([]string(nil), f.Scanners...), ObservationIDs: append([]string(nil), f.ObservationIDs...), AffectedEndpointCount: f.AffectedEndpointCount, AffectedInstanceCount: f.AffectedInstanceCount, ObservationCount: f.ObservationCount, AffectedEndpoints: append([]scanner.FindingEndpoint(nil), f.Endpoints...), VerificationMethod: strings.Join(f.Scanners, ", "), Verified: f.Status == scanner.StatusConfirmed}
}

func firstFindingEndpoint(f scanner.SecurityFinding) string {
	if len(f.Endpoints) > 0 {
		return f.Endpoints[0].Endpoint
	}
	return ""
}

func snapshotSummaries(snapshot *scanner.FindingsSnapshot) []VulnSummary {
	if snapshot == nil {
		return []VulnSummary{}
	}
	out := make([]VulnSummary, 0, len(snapshot.UniqueFindings))
	for _, f := range snapshot.UniqueFindings {
		out = append(out, securityFindingToSummary(f))
	}
	return out
}

func buildFindingsSnapshot(rec *ScanRecord, scanDir string) (*scanner.FindingsSnapshot, []error) {
	if rec == nil {
		return nil, []error{fmt.Errorf("nil scan record")}
	}
	legacy := make([]scanner.Finding, 0, len(rec.Vulns))
	if len(rec.ScannerRuns) == 0 {
		for _, v := range rec.Vulns {
			legacy = append(legacy, legacyFindingToScanner(v))
		}
	}
	snapshot, errs := scanner.BuildFindingsSnapshot(rec.ScannerRuns, legacy)
	if snapshot == nil {
		return nil, errs
	}
	scanner.ApplyFindingOverrides(snapshot, scanner.LoadFindingStatusOverrides(scanDir))
	return snapshot, errs
}

func rebuildFindingsSnapshot(rec *ScanRecord, scanDir string, persist bool) (*scanner.FindingsSnapshot, []error) {
	snapshot, errs := buildFindingsSnapshot(rec, scanDir)
	if snapshot == nil {
		return nil, errs
	}
	if persist {
		for _, validation := range scanner.ValidateSPAFallback(context.Background(), snapshot) {
			for i := range snapshot.UniqueFindings {
				if snapshot.UniqueFindings[i].Fingerprint == validation.Fingerprint && snapshot.UniqueFindings[i].Status == scanner.StatusPotential {
					snapshot.UniqueFindings[i].Status = scanner.StatusLikelyFalsePositive
					snapshot.UniqueFindings[i].ValidationReason = validation.Reason
				}
			}
		}
		snapshot.RecomputeSummary()
	}
	if persist {
		if err := scanner.SaveFindingsSnapshot(scanDir, snapshot); err != nil {
			errs = append(errs, err)
		}
	}
	return snapshot, errs
}

func normalizedVulnsForEntry(entry scanEntry) []VulnSummary {
	if snapshot, ok := scanner.LoadFindingsSnapshot(entry.dir); ok {
		return snapshotSummaries(snapshot)
	}
	return entry.rec.Vulns
}

func findingStatusOverride(snapshot *scanner.FindingsSnapshot, fingerprint string, status scanner.FindingStatus, reason string) error {
	if snapshot == nil {
		return fmt.Errorf("findings snapshot unavailable")
	}
	for i := range snapshot.UniqueFindings {
		if snapshot.UniqueFindings[i].Fingerprint == fingerprint {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("status reason is required")
			}
			snapshot.UniqueFindings[i].Status, snapshot.UniqueFindings[i].StatusReason = status, strings.TrimSpace(reason)
			snapshot.RecomputeSummary()
			return nil
		}
	}
	return fmt.Errorf("finding %q not found", fingerprint)
}

func updateFindingStatus(scanDir string, snapshot *scanner.FindingsSnapshot, fingerprint string, status scanner.FindingStatus, reason string) error {
	if err := findingStatusOverride(snapshot, fingerprint, status, reason); err != nil {
		return err
	}
	overrides := scanner.LoadFindingStatusOverrides(scanDir)
	overrides[fingerprint] = scanner.FindingStatusOverride{Status: status, Reason: strings.TrimSpace(reason), UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := scanner.SaveFindingStatusOverrides(scanDir, overrides); err != nil {
		return err
	}
	return scanner.SaveFindingsSnapshot(scanDir, snapshot)
}

package scanner

// This file contains the single deterministic correlation layer used by the
// report, API, and compatibility projections. Native scanner artifacts remain
// the source of truth; this snapshot is a derived, rebuildable index.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

const (
	FindingsSchemaVersion = 1
	FindingsEngineVersion = "deterministic-correlation-v1"
)

type DedupeScope string

const (
	DedupeHost           DedupeScope = "HOST"
	DedupeEndpoint       DedupeScope = "ENDPOINT"
	DedupeParameter      DedupeScope = "PARAMETER"
	DedupeService        DedupeScope = "SERVICE"
	DedupePackage        DedupeScope = "PACKAGE"
	DedupeSourceLocation DedupeScope = "SOURCE_LOCATION"
	DedupeContainer      DedupeScope = "CONTAINER"
	DedupeResource       DedupeScope = "RESOURCE"
)

type FindingStatus string

const (
	StatusObservation         FindingStatus = "OBSERVATION"
	StatusPotential           FindingStatus = "POTENTIAL"
	StatusConfirmed           FindingStatus = "CONFIRMED"
	StatusLikelyFalsePositive FindingStatus = "LIKELY_FALSE_POSITIVE"
	StatusFalsePositive       FindingStatus = "FALSE_POSITIVE"
	StatusRemediated          FindingStatus = "REMEDIATED"
	StatusAcceptedRisk        FindingStatus = "ACCEPTED_RISK"
)

type RawObservation struct {
	ID                string  `json:"id"`
	Scanner           string  `json:"scanner"`
	RuleID            string  `json:"rule_id,omitempty"`
	SourceID          string  `json:"source_id"`
	EvidenceReference string  `json:"evidence_reference,omitempty"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity,omitempty"`
	Target            string  `json:"target,omitempty"`
	Endpoint          string  `json:"endpoint,omitempty"`
	CanonicalEndpoint string  `json:"canonical_endpoint,omitempty"`
	Method            string  `json:"method,omitempty"`
	Parameter         string  `json:"parameter,omitempty"`
	ParameterLocation string  `json:"parameter_location,omitempty"`
	Protocol          string  `json:"protocol,omitempty"`
	Port              string  `json:"port,omitempty"`
	Package           string  `json:"package,omitempty"`
	PackageVersion    string  `json:"package_version,omitempty"`
	SourceLocation    string  `json:"source_location,omitempty"`
	Container         string  `json:"container,omitempty"`
	Resource          string  `json:"resource,omitempty"`
	Description       string  `json:"description,omitempty"`
	Evidence          string  `json:"evidence,omitempty"`
	Remediation       string  `json:"remediation,omitempty"`
	CVE               string  `json:"cve,omitempty"`
	CWE               string  `json:"cwe,omitempty"`
	CVSS              float64 `json:"cvss,omitempty"`
	SeverityUnrated   bool    `json:"severity_unrated,omitempty"`
	Scope             string  `json:"scope,omitempty"`
	ObservedAt        string  `json:"observed_at,omitempty"`
	ObservationKind   string  `json:"observation_kind,omitempty"`
}

type FindingEndpoint struct {
	Endpoint          string   `json:"endpoint,omitempty"`
	CanonicalEndpoint string   `json:"canonical_endpoint,omitempty"`
	Method            string   `json:"method,omitempty"`
	Parameter         string   `json:"parameter,omitempty"`
	ParameterLocation string   `json:"parameter_location,omitempty"`
	Scanner           string   `json:"scanner,omitempty"`
	ObservationIDs    []string `json:"observation_ids,omitempty"`
}

type SecurityFinding struct {
	ID                    string            `json:"id"`
	Fingerprint           string            `json:"fingerprint"`
	NormalizedType        string            `json:"normalized_type"`
	Title                 string            `json:"title"`
	DedupeScope           DedupeScope       `json:"dedupe_scope"`
	Target                string            `json:"target,omitempty"`
	Scope                 string            `json:"scope,omitempty"`
	Host                  string            `json:"host,omitempty"`
	Protocol              string            `json:"protocol,omitempty"`
	Port                  string            `json:"port,omitempty"`
	Severity              string            `json:"severity"`
	CVSS                  float64           `json:"cvss,omitempty"`
	CVE                   []string          `json:"cve,omitempty"`
	CWE                   []string          `json:"cwe,omitempty"`
	Scanners              []string          `json:"scanners,omitempty"`
	Status                FindingStatus     `json:"status"`
	StatusReason          string            `json:"status_reason,omitempty"`
	ObservationIDs        []string          `json:"observation_ids"`
	Endpoints             []FindingEndpoint `json:"endpoints,omitempty"`
	AffectedEndpointCount int               `json:"affected_endpoint_count"`
	AffectedInstanceCount int               `json:"affected_instance_count"`
	ObservationCount      int               `json:"observation_count"`
	FirstSeenAt           string            `json:"first_seen_at,omitempty"`
	LastSeenAt            string            `json:"last_seen_at,omitempty"`
	ValidationReason      string            `json:"validation_reason,omitempty"`
}

type FindingSummary struct {
	RawObservations        int            `json:"raw_observations"`
	UniqueFindings         int            `json:"unique_findings"`
	ActiveSecurityFindings int            `json:"active_security_findings"`
	Status                 map[string]int `json:"status"`
	Severity               map[string]int `json:"severity"`
}

type FindingsSnapshot struct {
	SchemaVersion   int               `json:"schema_version"`
	EngineVersion   string            `json:"engine_version"`
	GeneratedAt     string            `json:"generated_at"`
	SourceRuns      []Run             `json:"source_runs,omitempty"`
	RawObservations []RawObservation  `json:"raw_observations"`
	UniqueFindings  []SecurityFinding `json:"unique_findings"`
	Summary         FindingSummary    `json:"summary"`
}

type FindingStatusOverride struct {
	Status    FindingStatus `json:"status"`
	Reason    string        `json:"reason"`
	UpdatedAt string        `json:"updated_at"`
}

type FindingStatusOverrides map[string]FindingStatusOverride

func FindingsSnapshotPath(scanDir string) string {
	return filepath.Join(scanDir, "findings", "findings-v1.json")
}
func FindingStatusOverridesPath(scanDir string) string {
	return filepath.Join(scanDir, "findings", "status-overrides.json")
}

func FindingActive(status FindingStatus) bool {
	return status == StatusPotential || status == StatusConfirmed || status == StatusAcceptedRisk
}

func (s *FindingsSnapshot) RecomputeSummary() {
	s.Summary = FindingSummary{RawObservations: len(s.RawObservations), UniqueFindings: len(s.UniqueFindings), Status: map[string]int{}, Severity: map[string]int{}}
	for _, f := range s.UniqueFindings {
		s.Summary.Status[string(f.Status)]++
		if FindingActive(f.Status) {
			s.Summary.ActiveSecurityFindings++
			s.Summary.Severity[normalizeFindingSeverity(f.Severity)]++
		}
	}
}

func SaveFindingsSnapshot(scanDir string, snapshot *FindingsSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("nil findings snapshot")
	}
	if err := storage.EnsureSecureDir(filepath.Dir(FindingsSnapshotPath(scanDir))); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteAtomic(FindingsSnapshotPath(scanDir), append(data, '\n'))
}

func LoadFindingsSnapshot(scanDir string) (*FindingsSnapshot, bool) {
	data, err := os.ReadFile(FindingsSnapshotPath(scanDir))
	if err != nil {
		return nil, false
	}
	var snapshot FindingsSnapshot
	if json.Unmarshal(data, &snapshot) != nil || snapshot.SchemaVersion != FindingsSchemaVersion {
		return nil, false
	}
	return &snapshot, true
}

func LoadFindingStatusOverrides(scanDir string) FindingStatusOverrides {
	data, err := os.ReadFile(FindingStatusOverridesPath(scanDir))
	if err != nil {
		return FindingStatusOverrides{}
	}
	var out FindingStatusOverrides
	if json.Unmarshal(data, &out) != nil || out == nil {
		return FindingStatusOverrides{}
	}
	return out
}

func SaveFindingStatusOverrides(scanDir string, overrides FindingStatusOverrides) error {
	if err := storage.EnsureSecureDir(filepath.Dir(FindingStatusOverridesPath(scanDir))); err != nil {
		return err
	}
	data, err := json.MarshalIndent(overrides, "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteAtomic(FindingStatusOverridesPath(scanDir), append(data, '\n'))
}

type findingRule struct {
	Type        string
	Title       string
	Scope       DedupeScope
	Observation bool
	Confirmed   bool
}

var findingRules = map[string]findingRule{
	"missing_content_security_policy": {Type: "missing_content_security_policy", Title: "Missing Content Security Policy", Scope: DedupeHost},
	"missing_hsts":                    {Type: "missing_hsts", Title: "Missing HTTP Strict Transport Security", Scope: DedupeHost},
	"missing_security_header":         {Type: "missing_security_header", Scope: DedupeHost},
	"technology_detection":            {Type: "technology_detection", Scope: DedupeHost, Observation: true},
	"open_port":                       {Type: "open_port", Scope: DedupeService, Observation: true},
	"prometheus_metrics_exposure":     {Type: "prometheus_metrics_exposure", Title: "Prometheus Metrics Exposed", Scope: DedupeEndpoint},
	"sql_injection":                   {Type: "sql_injection", Title: "SQL Injection", Scope: DedupeParameter},
	"cross_site_scripting":            {Type: "cross_site_scripting", Title: "Cross-Site Scripting", Scope: DedupeParameter},
}

func normalizedFindingRule(f Finding) findingRule {
	text := strings.ToLower(strings.Join([]string{f.RuleID, f.Title, f.Description}, " "))
	switch {
	case strings.Contains(text, "content-security-policy") || strings.Contains(text, "content security policy"):
		return findingRules["missing_content_security_policy"]
	case strings.Contains(text, "strict-transport-security") || strings.Contains(text, "missing hsts"):
		return findingRules["missing_hsts"]
	case strings.Contains(text, "prometheus") || strings.Contains(text, "/metrics"):
		return findingRules["prometheus_metrics_exposure"]
	case strings.Contains(text, "sql injection") || strings.Contains(text, "sqli"):
		return findingRules["sql_injection"]
	case strings.Contains(text, "cross-site scripting") || strings.Contains(text, "xss"):
		return findingRules["cross_site_scripting"]
	case f.Scanner == "nmap" || strings.Contains(text, "open port"):
		return findingRules["open_port"]
	case strings.Contains(text, "technology") || strings.Contains(text, "wappalyzer") || strings.Contains(text, "juice shop") || strings.Contains(text, "fingerprint"):
		return findingRules["technology_detection"]
	}
	if cve := normalizeFindingTitle(f.CVE); cve != "" {
		r := findingRule{Type: "vulnerability_" + cve, Scope: DedupeEndpoint}
		if f.Parameter != "" {
			r.Scope = DedupeParameter
		}
		return r
	}
	r := findingRule{Type: normalizeFindingTitle(f.Title), Scope: DedupeEndpoint}
	if r.Type == "" {
		r.Type = strings.ToLower(strings.TrimSpace(f.Scanner)) + ":" + strings.ToLower(strings.TrimSpace(f.RuleID))
	}
	return r
}

func normalizeFindingTitle(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('_')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func normalizeFindingSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func findingSeverityRank(value string) int {
	switch normalizeFindingSeverity(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func normalizedFindingEndpoint(raw string) (string, string) {
	if observed, canonical, _, _, ok := canonicalizeAttackSurfaceURL(raw); ok {
		return observed, canonical
	}
	return strings.TrimSpace(raw), strings.TrimSpace(raw)
}

func findingAsset(f Finding, endpoint string) (host, protocol, port string) {
	parsed, err := url.Parse(endpoint)
	if err == nil && parsed.Host != "" {
		protocol, host, port = strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Hostname()), parsed.Port()
		if port == "" {
			if protocol == "https" {
				port = "443"
			} else if protocol == "http" {
				port = "80"
			}
		}
	}
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(f.Target))
	}
	return
}

func observationFromFinding(f Finding, run Run, index int) RawObservation {
	observed, canonical := normalizedFindingEndpoint(f.Endpoint)
	if observed == "" {
		observed = f.Endpoint
	}
	if canonical == "" {
		canonical = observed
	}
	rule := normalizedFindingRule(f)
	seed := strings.Join([]string{f.Scanner, f.Scope, f.RuleID, f.SourceID, canonical, strings.ToUpper(f.Method), f.Parameter, fmt.Sprint(index)}, "\x00")
	h := sha256.Sum256([]byte(seed))
	id := hex.EncodeToString(h[:16])
	seen := run.FinishedAt
	if seen == "" {
		seen = run.StartedAt
	}
	if seen == "" {
		seen = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return RawObservation{ID: id, Scanner: f.Scanner, RuleID: f.RuleID, SourceID: f.SourceID, EvidenceReference: f.EvidenceRef, Title: f.Title, Severity: f.Severity, SeverityUnrated: f.SeverityUnrated, Target: f.Target, Endpoint: observed, CanonicalEndpoint: canonical, Method: strings.ToUpper(f.Method), Parameter: f.Parameter, ParameterLocation: f.ParameterLocation, Protocol: f.Protocol, Port: f.Port, Package: f.Package, PackageVersion: f.PackageVersion, SourceLocation: f.SourceLocation, Container: f.Container, Resource: f.Resource, Description: f.Description, Evidence: f.Evidence, Remediation: f.Remediation, CVE: f.CVE, CWE: f.CWE, CVSS: f.CVSS, Scope: f.Scope, ObservedAt: seen, ObservationKind: rule.Type}
}

func findingFingerprint(f RawObservation, rule findingRule) string {
	host, protocol, port := findingAsset(Finding{Target: f.Target}, f.Endpoint)
	asset := strings.Join([]string{protocol, host, port}, "|")
	var locator string
	switch rule.Scope {
	case DedupeHost:
		locator = asset
	case DedupeParameter:
		_, canonical := normalizedFindingEndpoint(f.Endpoint)
		p, _ := url.Parse(canonical)
		path := canonical
		if p != nil && p.Path != "" {
			path = p.Path
		}
		locator = strings.Join([]string{asset, path, strings.ToUpper(f.Method), strings.ToLower(f.ParameterLocation), strings.ToLower(f.Parameter)}, "|")
	case DedupeService:
		locator = strings.Join([]string{host, protocol, port, strings.ToLower(f.Resource), strings.ToLower(f.Title)}, "|")
	case DedupePackage:
		locator = strings.Join([]string{f.Scope, strings.ToLower(f.Package), strings.ToLower(f.PackageVersion), strings.ToLower(f.Target)}, "|")
	case DedupeSourceLocation:
		locator = strings.Join([]string{f.Scope, f.SourceLocation, f.Target, f.Parameter}, "|")
	case DedupeContainer:
		locator = strings.Join([]string{f.Container, f.Package, f.PackageVersion}, "|")
	case DedupeResource:
		locator = strings.Join([]string{f.Resource, f.Target}, "|")
	default:
		_, canonical := normalizedFindingEndpoint(f.Endpoint)
		locator = strings.Join([]string{asset, canonical, strings.ToUpper(f.Method)}, "|")
	}
	h := sha256.Sum256([]byte(rule.Type + "|" + locator))
	return "sha256:" + hex.EncodeToString(h[:])
}

func addUniqueString(dst *[]string, value string) {
	if value != "" {
		for _, v := range *dst {
			if v == value {
				return
			}
		}
		*dst = append(*dst, value)
	}
}

func BuildFindingsSnapshot(runs []Run, legacy []Finding) (*FindingsSnapshot, []error) {
	snapshot := &FindingsSnapshot{SchemaVersion: FindingsSchemaVersion, EngineVersion: FindingsEngineVersion, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRuns: append([]Run(nil), runs...), RawObservations: []RawObservation{}}
	var errs []error
	for _, run := range runs {
		if (run.Status != "completed" && run.Status != "failed") || run.ArtifactPath == "" {
			continue
		}
		parsed, err := ParseRun(run)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", run.Scanner, err))
		}
		for i, f := range parsed {
			f.Scope = FindingScope(run)
			f.EvidenceRef = run.ArtifactPath + "#" + f.SourceID
			snapshot.RawObservations = append(snapshot.RawObservations, observationFromFinding(f, run, i))
		}
	}
	if len(snapshot.RawObservations) == 0 {
		for i, f := range legacy {
			snapshot.RawObservations = append(snapshot.RawObservations, observationFromFinding(f, Run{Scanner: f.Scanner, Scope: f.Scope}, i))
		}
	}
	groups := map[string]*SecurityFinding{}
	for _, o := range snapshot.RawObservations {
		f := Finding{Scanner: o.Scanner, RuleID: o.RuleID, Title: o.Title, Description: o.Description, Target: o.Target, Endpoint: o.Endpoint, Method: o.Method, Parameter: o.Parameter, ParameterLocation: o.ParameterLocation, Scope: o.Scope, Resource: o.Resource, Package: o.Package, PackageVersion: o.PackageVersion, SourceLocation: o.SourceLocation, Container: o.Container}
		rule := normalizedFindingRule(f)
		if rule.Title == "" {
			rule.Title = o.Title
		}
		fingerprint := findingFingerprint(o, rule)
		g := groups[fingerprint]
		if g == nil {
			h := sha256.Sum256([]byte(fingerprint))
			g = &SecurityFinding{ID: "finding-" + hex.EncodeToString(h[:8]), Fingerprint: fingerprint, NormalizedType: rule.Type, Title: firstNonEmpty(rule.Title, o.Title), DedupeScope: rule.Scope, Target: o.Target, Scope: o.Scope, Severity: o.Severity, CVSS: o.CVSS, Status: StatusPotential, FirstSeenAt: o.ObservedAt, LastSeenAt: o.ObservedAt}
			if rule.Observation {
				g.Status = StatusObservation
			}
			if rule.Confirmed {
				g.Status = StatusConfirmed
			}
			groups[fingerprint] = g
		}
		if findingSeverityRank(o.Severity) > findingSeverityRank(g.Severity) {
			g.Severity = o.Severity
		}
		if o.CVSS > g.CVSS {
			g.CVSS = o.CVSS
		}
		addUniqueString(&g.Scanners, o.Scanner)
		addUniqueString(&g.CVE, o.CVE)
		addUniqueString(&g.CWE, o.CWE)
		g.ObservationIDs = append(g.ObservationIDs, o.ID)
		g.ObservationCount++
		if o.ObservedAt < g.FirstSeenAt || g.FirstSeenAt == "" {
			g.FirstSeenAt = o.ObservedAt
		}
		if o.ObservedAt > g.LastSeenAt {
			g.LastSeenAt = o.ObservedAt
		}
		found := false
		for i := range g.Endpoints {
			if g.Endpoints[i].CanonicalEndpoint == o.CanonicalEndpoint && g.Endpoints[i].Method == o.Method && g.Endpoints[i].Parameter == o.Parameter {
				g.Endpoints[i].ObservationIDs = append(g.Endpoints[i].ObservationIDs, o.ID)
				found = true
				break
			}
		}
		if !found {
			g.Endpoints = append(g.Endpoints, FindingEndpoint{Endpoint: o.Endpoint, CanonicalEndpoint: o.CanonicalEndpoint, Method: o.Method, Parameter: o.Parameter, ParameterLocation: o.ParameterLocation, Scanner: o.Scanner, ObservationIDs: []string{o.ID}})
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		g.AffectedEndpointCount = len(g.Endpoints)
		g.AffectedInstanceCount = g.ObservationCount
		snapshot.UniqueFindings = append(snapshot.UniqueFindings, *g)
	}
	snapshot.RecomputeSummary()
	return snapshot, errs
}

func ApplyFindingOverrides(snapshot *FindingsSnapshot, overrides FindingStatusOverrides) {
	for i := range snapshot.UniqueFindings {
		if o, ok := overrides[snapshot.UniqueFindings[i].Fingerprint]; ok {
			snapshot.UniqueFindings[i].Status, snapshot.UniqueFindings[i].StatusReason = o.Status, o.Reason
		}
	}
	snapshot.RecomputeSummary()
}

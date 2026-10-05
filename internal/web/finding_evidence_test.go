package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func TestSanitizeFindingObservationRedactsSecretsAndBoundsEvidence(t *testing.T) {
	o := scanner.RawObservation{
		Target:   "https://user:pass@example.test/a?access_token=topsecret&item=42#frag",
		Endpoint: "https://example.test/a?session_id=session-secret&item=42",
		Evidence: "Authorization: Bearer bearer-secret\nCookie: sid=cookie-secret\n{\"api_key\":\"json-secret\",\"email\":\"person@example.test\"}",
	}
	got := sanitizeFindingObservation(o)
	for _, secret := range []string{"user:pass", "topsecret", "session-secret", "bearer-secret", "cookie-secret", "json-secret", "person@example.test", "#frag"} {
		if strings.Contains(got.Target+got.Endpoint+got.Evidence, secret) {
			t.Errorf("sanitized observation still contains %q: %+v", secret, got)
		}
	}
	if !strings.Contains(got.Target, "item=42") || !strings.Contains(got.Target, "[REDACTED]") {
		t.Fatalf("useful URL details were lost: %q", got.Target)
	}
	long := sanitizeEvidenceText(strings.Repeat("x", maxFindingEvidenceRunes+25))
	if n := len([]rune(long)); n > maxFindingEvidenceRunes+20 || !strings.Contains(long, "[truncated]") {
		t.Fatalf("evidence was not bounded: runes=%d tail=%q", n, long[len(long)-20:])
	}
}

func TestReportEvidenceIncludesEveryObservationLocationAndReference(t *testing.T) {
	snapshot := &scanner.FindingsSnapshot{
		RawObservations: []scanner.RawObservation{
			{ID: "o1", Scanner: "zap", SourceID: "zap:1", EvidenceReference: "zap.json#1", Endpoint: "https://example.test/items?token=secret", Method: "GET", Parameter: "id", ParameterLocation: "query", Evidence: "id was reflected"},
			{ID: "o2", Scanner: "semgrep", SourceID: "semgrep:rule", EvidenceReference: "semgrep.json#1", SourceLocation: "src/auth.go:27", Evidence: "unsafe call"},
			{ID: "o3", Scanner: "trivy", SourceID: "trivy:CVE-1", Package: "libfoo", PackageVersion: "1.2.3", Evidence: "fixed version 1.2.4"},
			{ID: "o4", Scanner: "nmap", SourceID: "nmap:443", Protocol: "tcp", Port: "443", Target: "example.test", Evidence: "nginx 1.0"},
			{ID: "o5", Scanner: "prowler", SourceID: "prowler:bucket", Resource: "arn:aws:s3:::example", Container: "web:latest"},
		},
		UniqueFindings: []scanner.SecurityFinding{{ID: "finding-1", Title: "Multiple", Severity: "high", Scanners: []string{"zap", "semgrep", "trivy", "nmap", "prowler"}, ObservationIDs: []string{"o1", "o2", "o3", "o4", "o5"}}},
	}
	finding := fallbackSnapshotFindings(snapshot)[0]
	if len(finding.EvidenceItems) != 5 {
		t.Fatalf("evidence observations=%d, want 5", len(finding.EvidenceItems))
	}
	text := renderFindingEvidence(finding)
	for _, want := range []string{"https://example.test/items", "method=GET", "query parameter=id", "src/auth.go:27", "libfoo@1.2.3", "service=tcp/443", "arn:aws:s3:::example", "Evidence reference: zap.json#1", "id was reflected", "Evidence excerpt: Not provided by scanner"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered evidence missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "token=secret") {
		t.Fatalf("report evidence leaked sensitive URL value: %s", text)
	}
}

func TestReportEvidenceLabelsMissingLocationAndEvidence(t *testing.T) {
	finding := reportFindingsToVulns([]reportFinding{{SourceID: "old", Scanner: "unknown"}})[0]
	if !strings.Contains(finding.TechnicalAnalysis, "Affected location: Not provided by scanner") || !strings.Contains(finding.TechnicalAnalysis, "Evidence excerpt: Not provided by scanner") {
		t.Fatalf("missing data was not made explicit: %q", finding.TechnicalAnalysis)
	}
}

func TestFindingObservationAPIReturnsRedactedLocationAndEvidence(t *testing.T) {
	s := newTestServer(t, nil)
	dir := filepath.Join(s.dataDir, "evidence-test")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := json.Marshal(ScanRecord{ID: "evidence-test", Target: "example.test", Status: "finished"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := &scanner.FindingsSnapshot{
		SchemaVersion:   scanner.FindingsSchemaVersion,
		RawObservations: []scanner.RawObservation{{ID: "obs-1", Scanner: "zap", SourceID: "zap:1", Title: "Issue", Endpoint: "https://example.test/?api_key=secret", Evidence: "Authorization: Bearer secret-token"}},
		UniqueFindings:  []scanner.SecurityFinding{{ID: "finding-1", Title: "Issue", Severity: "high", Status: scanner.StatusPotential, Target: "example.test", Endpoints: []scanner.FindingEndpoint{{Endpoint: "https://example.test/?token=secret"}}, ObservationIDs: []string{"obs-1"}}},
	}
	if err := scanner.SaveFindingsSnapshot(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/api/scans/evidence-test/findings/finding-1/observations", "/api/scans/evidence-test/findings/finding-1"} {
		w := httptest.NewRecorder()
		s.handleFindingsAPI(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", route, w.Code, w.Body.String())
		}
		for _, secret := range []string{"api_key=secret", "token=secret", "secret-token"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Errorf("%s leaked %q: %s", route, secret, w.Body.String())
			}
		}
	}
}

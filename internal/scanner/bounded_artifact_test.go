package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundArtifactRejectsOversizedMetadataWithoutDestroyingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	original := `{"alerts":[],"metadata":"` + strings.Repeat("x", 200) + `"}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "zap", 40); !bounded || err == nil {
		t.Fatal("unbounded metadata accepted", bounded, err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatal("diagnostic artifact changed")
	}
}
func TestBoundArtifactRetainsPrefixAndExactLargeNumbers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	original := `{"vulnerabilities":{"a":[{"id":9007199254740993,"evidence":"first"},{"evidence":"second"}],"b":[{"evidence":"third"}]}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "wapiti", 100); !bounded || err != nil {
		t.Fatal(bounded, err)
	}
	data, _ := os.ReadFile(path)
	if len(data) > 100 || !json.Valid(data) || !strings.Contains(string(data), "9007199254740993") || strings.Contains(string(data), "third") {
		t.Fatalf("invalid retained prefix %s", data)
	}
}
func TestBoundJSONLDoesNotRetainCutOrMalformedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.jsonl")
	if err := os.WriteFile(path, []byte("{\"id\":1}\n{\"id\":2,\"evidence\":\"long\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "nuclei", 15); !bounded || err != nil {
		t.Fatal(bounded, err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "{\"id\":1}\n" {
		t.Fatalf("cut record retained %s", data)
	}
	if err := os.WriteFile(path, []byte("{invalid}\n"+strings.Repeat("x", 50)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := boundWebArtifact(path, "nuclei", 20); err == nil {
		t.Fatal("malformed retained record accepted")
	}
}
func TestBoundArtifactReportsReadFailure(t *testing.T) {
	// /dev/null is not a regular output artifact. A directory exercises the
	// read failure without relying on Unix permission behavior under root.
	if _, err := boundWebArtifact(t.TempDir(), "zap", 1); err == nil {
		t.Fatal("artifact read failure hidden")
	}
}

func TestBoundOpenVASRetainsCompleteNativeResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.xml")
	original := `<get_reports_response status="200"><report id="native-report"><report><results><result id="first"><name>First</name><host>127.0.0.1</host><port>443/tcp</port><severity>7.5</severity><description>first evidence</description><nvt oid="1"/></result><result id="second"><name>Second</name><description>` + strings.Repeat("second evidence", 30) + `</description></result></results><result_count>2</result_count></report></report></get_reports_response>`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "openvas", 450); !bounded || err != nil {
		t.Fatal(bounded, err)
	}
	data, _ := os.ReadFile(path)
	if len(data) > 450 || !strings.Contains(string(data), `id="native-report"`) || strings.Contains(string(data), `id="second"`) {
		t.Fatalf("invalid bounded native report: %s", data)
	}
	findings, err := parseOpenVAS(path)
	if err != nil || len(findings) != 1 || findings[0].SourceID != "openvas:first" {
		t.Fatalf("partial results: %+v %v", findings, err)
	}
}

func TestBoundVulsRetainsCompleteCVEs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vuls.json")
	original := `{"serverName":"local-lab","scannedCves":{"CVE-2026-0001":{"title":"first","cvss3Score":7.5},"CVE-2026-0002":{"summary":"` + strings.Repeat("second evidence", 30) + `"}}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "vuls", 150); !bounded || err != nil {
		t.Fatal(bounded, err)
	}
	data, _ := os.ReadFile(path)
	if !json.Valid(data) || len(data) > 150 {
		t.Fatalf("cut JSON: %s", data)
	}
	findings, err := parseVuls(path)
	if err != nil || len(findings) != 1 || findings[0].SourceID != "vuls:CVE-2026-0001:local-lab" {
		t.Fatalf("partial results: %+v %v", findings, err)
	}
}

func TestArtifactRedactionIsAtomicAndFailureIsNotUsableSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(`{"evidence":"private-secret"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := redactArtifact(path, []string{"private-secret"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if !json.Valid(data) || strings.Contains(string(data), "private-secret") || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe sanitized artifact: %s mode %v", data, info.Mode())
	}
	directory := t.TempDir()
	if err := redactArtifact(directory, []string{"private-secret"}); err == nil {
		t.Fatal("nonregular artifact accepted")
	}
	run := Run{Status: "completed", ArtifactPath: directory}
	invalidateUnsafeArtifact(&run)
	if run.Status != "failed" || run.ArtifactPath != "" || run.ExecutionOutcome != "SUCCESS" || run.ParserOutcome != "FAILED" || run.Outcome != "PARSER_FAILED" {
		t.Fatalf("unsafe artifact counted as success: %+v", run)
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatal("artifact failure deleted a directory")
	}
	timeout := Run{Status: "cancelled", ExecutionOutcome: "TIMEOUT", Outcome: "TIMEOUT", ArtifactPath: directory, Reason: "scanner timeout"}
	invalidateUnsafeArtifact(&timeout)
	if timeout.Outcome != "TIMEOUT" || timeout.ExecutionOutcome != "TIMEOUT" || timeout.Reason != "scanner timeout" {
		t.Fatalf("artifact failure replaced timeout: %+v", timeout)
	}
}

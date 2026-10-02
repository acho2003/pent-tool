package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestSSLyzeParserReportsOnlyCompletedDeprecatedProtocols(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslyze.json")
	data := `{"server_scan_results":[{"server_location":{"hostname":"api.example.test","port":8443},"scan_status":"COMPLETED","scan_result":{"tls_1_0_cipher_suites":{"status":"COMPLETED","result":{"is_tls_version_supported":true}},"tls_1_1_cipher_suites":{"status":"ERROR","result":{"is_tls_version_supported":true}}}}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseSSLyze(path)
	if err != nil || len(findings) != 1 || findings[0].Target != "api.example.test" || findings[0].Port != "8443" || findings[0].Title != "TLS 1.0 is enabled" {
		t.Fatalf("SSLyze findings=%+v err=%v", findings, err)
	}
}

func TestSSLyzeBuilderPreservesApprovedSNIAndPort(t *testing.T) {
	cfg := assessment.Normalize(assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/app"}}, ApprovedOrigins: []assessment.ApprovedOrigin{{TargetID: "app", Scheme: "https", Host: "api.example.test", Port: 8443, PathPrefix: "/v1"}}})
	scope := assessment.AppScopeForTarget(cfg, "app")
	spec := buildSSLyze(Request{Target: "https://api.example.test:8443", ScanDir: t.TempDir(), AppScope: &scope}, Config{SSLyzePath: "sslyze"})
	if spec.notApp != "" || spec.args[len(spec.args)-1] != "api.example.test:8443" || !strings.Contains(strings.Join(spec.args, " "), "--json_out=") {
		t.Fatalf("TLS service command: %+v", spec)
	}
}

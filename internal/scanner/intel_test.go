package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acho2003/pent-tool/internal/assessment"
)

func intelTestServer(t *testing.T, provider string, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	previous := intelBase[provider]
	intelBase[provider] = server.URL
	t.Cleanup(func() { intelBase[provider] = previous; server.Close() })
}

func runIntel(t *testing.T, id, target string) (Run, []Finding) {
	t.Helper()
	provider, ok := intelProviderByID(id)
	if !ok {
		t.Fatalf("unknown provider %s", id)
	}
	run := intelRunner{provider}.Run(context.Background(), Request{Target: target, ScanDir: t.TempDir()}, Config{}, nil)
	if run.Status != "completed" {
		return run, nil
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatalf("parse %s: %v", id, err)
	}
	return run, findings
}

func TestIntelLookupIsUnavailableUntilItsKeyIsSet(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "")
	if IntelAvailability()["intel-shodan"] {
		t.Fatal("shodan is available without a key")
	}
	if reason := IntelUnavailableReason("intel-shodan"); !strings.Contains(reason, "SHODAN_API_KEY") {
		t.Fatalf("reason does not name the key: %q", reason)
	}
	run, _ := runIntel(t, "intel-shodan", "8.8.8.8")
	if run.Status != "not_applicable" || run.GapKind != GapToolUnavailable {
		t.Fatalf("run without key: status %q gap %q", run.Status, run.GapKind)
	}
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeNetwork}, Targets: []assessment.Target{{ID: "h", Kind: assessment.KindIP, Value: "8.8.8.8"}}, ScannerSelection: assessment.ScannerSelection{Variants: []string{"intel-shodan"}}}
	planned := func() bool {
		for _, job := range PlanAssessment(PlanInput{Config: cfg, Availability: IntelAvailability()}).Jobs {
			if job.Scanner == "intel-shodan" {
				return true
			}
		}
		return false
	}
	if planned() {
		t.Fatal("an unavailable lookup was planned as a job")
	}
	t.Setenv("SHODAN_API_KEY", "k")
	if !planned() {
		t.Fatal("a selected lookup with its key set was not planned")
	}
	cfg.ScannerSelection = assessment.ScannerSelection{}
	if planned() {
		t.Fatal("a lookup ran without being selected")
	}
	t.Setenv("SHODAN_API_KEY", "")
	if !IntelAvailability()["intel-crtsh"] {
		t.Fatal("keyless crt.sh lookup should be available")
	}
	for _, def := range ScannerRegistry() {
		if IsIntelScanner(def.ID) && (def.DefaultSelection != "optional" || def.Group != GroupIntel || !def.Selectable) {
			t.Fatalf("%s must be an optional, selectable threat-intel scanner: %+v", def.ID, def)
		}
	}
}

func TestShodanReportsServicesAndCVEsWithoutLeakingTheKey(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "sekret-key")
	intelTestServer(t, "shodan", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shodan/host/8.8.8.8" || r.URL.Query().Get("key") != "sekret-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"vulns":["CVE-2021-41773"],"data":[{"port":443,"transport":"tcp","product":"nginx","version":"1.18.0","vulns":{"CVE-2023-44487":{}}}]}`))
	})
	run, findings := runIntel(t, "intel-shodan", "https://8.8.8.8:443/app")
	if run.Status != "completed" || len(findings) != 3 {
		t.Fatalf("status %q reason %q findings %d", run.Status, run.Reason, len(findings))
	}
	artifact, _ := os.ReadFile(run.ArtifactPath)
	if strings.Contains(string(artifact)+run.Reason, "sekret-key") {
		t.Fatal("API key leaked into the artifact or reason")
	}
	if findings[0].Severity != "info" || !strings.Contains(findings[0].Evidence, "443/tcp nginx 1.18.0") || findings[1].CVE == "" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	t.Setenv("SHODAN_API_KEY", "wrong")
	run, _ = runIntel(t, "intel-shodan", "8.8.8.8")
	if run.Status != "failed" || strings.Contains(run.Reason, "wrong") || !strings.Contains(run.Reason, "rejected") {
		t.Fatalf("rejected key: status %q reason %q", run.Status, run.Reason)
	}
}

func TestIntelProvidersParseTheirResponses(t *testing.T) {
	for _, key := range []string{"GREYNOISE_API_KEY", "ABUSEIPDB_API_KEY", "SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET", "HIBP_API_KEY", "CLOUDFLARE_API_TOKEN", "SOCKET_API_TOKEN", "CENSYS_API_TOKEN", "DEHASHED_API_KEY", "GITHUB_TOKEN"} {
		t.Setenv(key, "k")
	}
	reply := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
	}
	intelTestServer(t, "greynoise", reply(`{"noise":true,"classification":"malicious","name":"unknown","last_seen":"2026-11-01"}`))
	intelTestServer(t, "abuseipdb", reply(`{"data":{"abuseConfidenceScore":80,"totalReports":12}}`))
	intelTestServer(t, "censys", reply(`{"result":{"resource":{"services":[{"port":22,"protocol":"SSH","transport_protocol":"TCP"}]}}}`))
	intelTestServer(t, "shadowserver", func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Get("HMAC2")) != 64 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`[{"type":"vulnerable service","tag":"missing bcp38 filtering","timestamp":"2026-11-15 09:39:21"},{"tag":"missing bcp38 filtering","timestamp":"2026-11-14 05:05:58"}]`))
	})
	intelTestServer(t, "crtsh", reply(`[{"name_value":"staging.example.com\n*.example.com"},{"name_value":"other.test"}]`))
	intelTestServer(t, "hibp", reply(`{"alice":["Adobe","LinkedIn"],"bob":["Adobe"]}`))
	intelTestServer(t, "github", reply(`{"total_count":2,"items":[{"repository":{"full_name":"someone/dotfiles"}}]}`))
	intelTestServer(t, "dehashed", reply(`{"total":7}`))
	intelTestServer(t, "cloudflare", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/settings"):
			_, _ = w.Write([]byte(`{"result":[{"id":"ssl","value":"flexible"},{"id":"min_tls_version","value":"1.0"},{"id":"always_use_https","value":"off"},{"id":"hsts","value":{"enabled":false}}]}`))
		case strings.HasSuffix(r.URL.Path, "/dns_records"):
			_, _ = w.Write([]byte(`{"result":[{"name":"example.com","type":"A","proxied":true},{"name":"origin.example.com","type":"A","proxied":false}]}`))
		default:
			_, _ = w.Write([]byte(`{"result":[{"id":"zone1"}]}`))
		}
	})
	intelTestServer(t, "socket", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"left-pad","version":"1.0.0","alerts":[{"type":"malware","severity":"critical","category":"supplyChainRisk"},{"type":"unmaintained","severity":"low","category":"maintenance"}]}` + "\n" + `{"namespace":"@scope","name":"pkg","version":"2.0.0","alerts":[]}` + "\n"))
	})
	intelTestServer(t, "depsdev", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/projects/") {
			_, _ = w.Write([]byte(`{"scorecard":{"overallScore":2.1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"isDeprecated":true,"relatedProjects":[{"projectKey":{"id":"github.com/a/b"},"relationType":"SOURCE_REPO"}]}`))
	})
	source := t.TempDir()
	_ = os.WriteFile(filepath.Join(source, "package.json"), []byte(`{"dependencies":{"left-pad":"^1.0.0","@scope/pkg":"2.0.0"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(source, "package-lock.json"), []byte(`{"packages":{"node_modules/left-pad":{"version":"1.0.0"},"node_modules/@scope/pkg":{"version":"2.0.0"}}}`), 0o600)

	for _, tc := range []struct {
		id, target string
		want       int
		severity   string
	}{
		{"intel-greynoise", "8.8.8.8", 1, "high"},
		{"intel-abuseipdb", "8.8.8.8", 1, "high"},
		{"intel-censys", "8.8.8.8", 1, "info"},
		{"intel-shadowserver", "8.8.8.8", 1, "medium"},
		{"intel-crtsh", "https://example.com/login", 1, "info"},
		{"intel-hibp", "www.example.com", 1, "medium"},
		{"intel-github-leaks", "example.com", 1, "low"},
		{"intel-dehashed", "example.com", 1, "medium"},
		{"intel-cloudflare", "app.example.com", 4, "high"},
		{"intel-socket", source, 1, "critical"},
		{"intel-depsdev", source, 4, "low"},
	} {
		run, findings := runIntel(t, tc.id, tc.target)
		if run.Status != "completed" || len(findings) != tc.want || findings[0].Severity != tc.severity || findings[0].Scanner != tc.id {
			t.Errorf("%s: status %q reason %q findings %+v", tc.id, run.Status, run.Reason, findings)
		}
	}
	if _, findings := runIntel(t, "intel-hibp", "www.example.com"); len(findings) == 1 && strings.Contains(findings[0].Evidence, "alice") {
		t.Error("HIBP account names must not be stored")
	}
	for _, tc := range [][2]string{{"intel-shodan", "10.0.0.5"}, {"intel-hibp", "8.8.8.8"}, {"intel-socket", t.TempDir()}} {
		if run, _ := runIntel(t, tc[0], tc[1]); run.Status != "not_applicable" {
			t.Errorf("%s on %s: status %q, want not_applicable", tc[0], tc[1], run.Status)
		}
	}
}

func TestSubfinderProviderConfigHoldsOnlyConfiguredKeys(t *testing.T) {
	for _, key := range []string{"SECURITYTRAILS_API_KEY", "CHAOS_API_KEY", "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "GITHUB_TOKEN"} {
		t.Setenv(key, "")
	}
	if path, _ := subfinderProviderConfig(); path != "" {
		t.Fatal("a provider file was written without any key")
	}
	t.Setenv("SECURITYTRAILS_API_KEY", "st-key")
	path, cleanup := subfinderProviderConfig()
	data, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data)) != `securitytrails: ["st-key"]` {
		t.Fatalf("provider file: %q", data)
	}
	cleanup()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("provider file was not removed")
	}
}

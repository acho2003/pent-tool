package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestNiktoBudgetRetainsPartialFindings(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-nikto")
	script := "#!/bin/sh\n" +
		"out=\nwhile [ $# -gt 0 ]; do if [ \"$1\" = -output ]; then shift; out=$1; fi; shift; done\n" +
		"printf '%s' '[{\"host\":\"example.test\",\"port\":\"80\",\"id\":\"123\",\"method\":\"GET\",\"uri\":\"/found\",\"message\":\"Issue\"}]' > \"$out.json\"\n" +
		"echo '+ ERROR: Host maximum execution time of 540 seconds reached'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	spec := buildNikto(Request{Target: "http://example.test/", ScanDir: dir}, Config{NiktoPath: bin})
	run := executeSpec(context.Background(), "nikto", Request{Target: "http://example.test/", ScanDir: dir}, Config{}, spec, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "partial results") {
		t.Fatalf("budget result = %+v", run)
	}
	findings, errs := ParseRuns([]Run{run})
	if len(errs) != 0 || len(findings) != 1 || findings[0].Endpoint != "http://example.test/found" {
		t.Fatalf("partial Nikto findings = %+v, errors = %v", findings, errs)
	}
}

func TestBuildNiktoIsBoundedAndIsolated(t *testing.T) {
	dir := t.TempDir()
	spec := buildNikto(Request{Target: "https://Example.test:8443/", ScanDir: dir}, Config{NiktoPath: "nikto", NiktoTimeout: 30 * time.Minute})
	if spec.notApp != "" || spec.timeout != niktoMaxDuration {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	want := []string{"-config", filepath.Join(dir, "scanner-output", "nikto", "nikto.conf"), "-host", "https://Example.test:8443/", "-nointeractive", "-nocheck", "-maxtime", "540s", "-timeout", "5", "-Pause", "1", "-Cgidirs", "none", "-Tuning", "123b", "-Format", "json", "-output", filepath.Join(dir, "scanner-output", "nikto", "results")}
	if !reflect.DeepEqual(spec.args, want) {
		t.Fatalf("Nikto args = %#v, want %#v", spec.args, want)
	}
	for _, arg := range spec.args {
		if arg == "-followredirects" || arg == "upload" || arg == "injection" || arg == "dos" || arg == "sqli" || arg == "authbypass" || arg == "cmdexec" {
			t.Fatalf("unsafe/unbounded option included: %q", arg)
		}
	}
	if err := spec.prepare(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(spec.args[1])
	if err != nil || !strings.Contains(string(data), "CHECKMETHODS=GET") || !strings.Contains(string(data), "UPDATES=no") || strings.Contains(string(data), "RFIURL=") {
		t.Fatalf("isolated config not written: data=%q err=%v", data, err)
	}
	if spec.artifact != filepath.Join(dir, "scanner-output", "nikto", "results.json") || spec.partialMarker == "" {
		t.Fatalf("unexpected Nikto artifact or partial marker: %+v", spec)
	}
	info, err := os.Stat(spec.args[1])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %v, err=%v", info.Mode().Perm(), err)
	}
}

func TestBuildNiktoRejectsTargetsOutsideRootHTTPOrigin(t *testing.T) {
	for _, target := range []string{
		"https://example.test/admin", "https://example.test/?x=1", "https://user:pass@example.test/",
		"https://example.test/#fragment", "ftp://example.test/", "https://example.test:bad/",
		// A bare target must be a plain host/IP/CIDR, never one carrying a path,
		// port, or scheme-like text.
		"example.test/admin", "example.test:8080", "evil.test;id",
	} {
		spec := buildNikto(Request{Target: target, ScanDir: t.TempDir()}, Config{NiktoPath: "nikto"})
		if spec.notApp == "" {
			t.Errorf("target %q was accepted", target)
		}
	}
	// A bare host, IP, or domain is now a valid network target (probed at its
	// HTTP root), so it must be accepted rather than rejected.
	if spec := buildNikto(Request{Target: "example.test", ScanDir: t.TempDir()}, Config{NiktoPath: "nikto", NiktoTimeout: time.Minute}); spec.notApp != "" {
		t.Errorf("bare domain was rejected: %s", spec.notApp)
	}
}

func TestBuildNiktoThoroughHasNoRequestPause(t *testing.T) {
	spec := buildNikto(Request{Target: "http://example.test/", ScanDir: t.TempDir(), Profile: ProfileThorough}, Config{NiktoPath: "nikto", NiktoTimeout: time.Second})
	if spec.timeout != 0 {
		t.Fatalf("thorough Nikto timeout = %s, want no overall deadline", spec.timeout)
	}
	for _, arg := range spec.args {
		if arg == "-Pause" || arg == "-maxtime" {
			t.Fatalf("thorough Nikto must not set a request pause or host deadline: %v", spec.args)
		}
	}
}

// Nikto requests its own fixed test paths and cannot honour route exclusions,
// so any configured exclusion refuses it with a visible excluded gap.
func TestNiktoRestrictedWhenExclusionsConfigured(t *testing.T) {
	origins := []assessment.ApprovedOrigin{{Scheme: "http", Host: "example.test", PathPrefix: "/"}}
	excluded := assessment.NewAppScope(origins, assessment.Exclusion{PathPattern: "/logout"})
	cfg := Config{NiktoPath: "nikto", NiktoTimeout: time.Minute}
	req := Request{Target: "http://example.test/", ScanDir: t.TempDir(), TypedAssessment: true, AppScope: &excluded}
	spec := buildNikto(req, cfg)
	if spec.notApp == "" || len(spec.args) != 0 || !strings.Contains(spec.notApp, "exclusion") {
		t.Fatalf("Nikto with exclusions = %+v, want a policy refusal", spec)
	}
	var events []Event
	run := niktoRunner{}.Run(context.Background(), req, cfg, func(e Event) { events = append(events, e) })
	if run.Status != "not_applicable" || run.GapKind != GapExcluded || run.Reason != spec.notApp {
		t.Fatalf("restricted Nikto run = %+v", run)
	}
	if len(events) != 1 || events[0].Run.GapKind != GapExcluded {
		t.Fatalf("restricted Nikto events = %+v", events)
	}
	if restricted, reason := AdapterPolicyRestriction("nikto", assessment.AssessmentConfig{Exclusions: []assessment.Exclusion{{PathPattern: "/logout"}}}); !restricted || reason != spec.notApp {
		t.Fatalf("AdapterPolicyRestriction = %v %q, want %q", restricted, reason, spec.notApp)
	}

	// Without exclusions the root-only behaviour is unchanged, scope or not.
	plain := assessment.NewAppScope(origins)
	for _, scope := range []*assessment.AppScope{nil, &plain} {
		ok := buildNikto(Request{Target: "http://example.test/", ScanDir: t.TempDir(), AppScope: scope}, cfg)
		if ok.notApp != "" || !hasArg(ok.args, "-host") {
			t.Fatalf("unrestricted Nikto spec = %+v", ok)
		}
		run := niktoRunner{}.Run(context.Background(), Request{Target: "ftp://example.test/", ScanDir: t.TempDir(), AppScope: scope}, cfg, nil)
		if run.Status != "not_applicable" || run.GapKind != "" {
			t.Fatalf("non-policy refusal must not be tagged as a policy gap: %+v", run)
		}
	}
}

func TestParseNiktoSupportsNestedAndSingleFindingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nikto.json")
	input := `[{"host":"example.test","port":"8443","ssl":true,"vulnerabilities":[{"id":"123","method":"GET","url":"/backup.zip","msg":"Backup archive exposed CVE-2024-12345","refs":"CVE-2024-12345"}]},{"host":"other.test","port":"80","id":"456","method":"GET","uri":"/server-info","message":"Server information disclosure"}]`
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseNikto(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings: %+v", len(findings), findings)
	}
	if findings[0].Endpoint != "https://example.test:8443/backup.zip" || findings[0].CVE != "CVE-2024-12345" || !findings[0].SeverityUnrated {
		t.Fatalf("nested issue lost location or CVE: %+v", findings[0])
	}
	if findings[1].Endpoint != "http://other.test/server-info" || findings[1].Evidence != "Nikto test 456 (GET)" {
		t.Fatalf("single issue parse incorrect: %+v", findings[1])
	}
}

func TestParseNiktoReportsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nikto.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseNikto(path); err == nil {
		t.Fatal("expected JSON parse error")
	}
}

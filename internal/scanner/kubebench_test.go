package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildKubeBench_ReadOnlyRun(t *testing.T) {
	spec := buildKubeBench(Request{ScanDir: t.TempDir()}, Config{KubeBenchPath: "/usr/bin/kube-bench", KubeBenchTimeout: time.Minute})
	if spec.notApp != "" {
		t.Fatalf("unexpected notApp: %s", spec.notApp)
	}
	if !hasArg(spec.args, "run") || !hasArg(spec.args, "--json") {
		t.Errorf("expected read-only `run --json`; args=%v", spec.args)
	}
	// FAIL/WARN make kube-bench exit non-zero; that must count as a completed audit.
	if !spec.okExit[1] || !spec.okExit[2] {
		t.Errorf("kube-bench non-zero exit (findings present) must be treated as success")
	}
}

func TestParseKubeBench_FailAndWarnBecomeFindings(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "results.json")
	body := `{"Controls":[{"id":"1","text":"Control Plane Security","tests":[
	  {"section":"1.1","desc":"API Server","results":[
	    {"test_number":"1.1.1","test_desc":"Ensure API server pod file perms","status":"FAIL","remediation":"chmod 600","scored":true},
	    {"test_number":"1.1.2","test_desc":"Ensure anonymous-auth off","status":"WARN","remediation":"set --anonymous-auth=false","scored":false},
	    {"test_number":"1.1.3","test_desc":"Ensure TLS","status":"PASS","scored":true}
	  ]}
	]}]}`
	if err := os.WriteFile(art, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := parseKubeBench(art)
	if err != nil {
		t.Fatalf("parseKubeBench: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (FAIL+WARN, not PASS)", len(findings))
	}
	byEP := map[string]Finding{}
	for _, f := range findings {
		byEP[f.Endpoint] = f
		if f.Scanner != "kube-bench" {
			t.Errorf("scanner = %q", f.Scanner)
		}
	}
	if byEP["1.1.1"].Severity != "medium" {
		t.Errorf("scored FAIL should be medium, got %q", byEP["1.1.1"].Severity)
	}
	if byEP["1.1.2"].Severity != "low" {
		t.Errorf("WARN should be low, got %q", byEP["1.1.2"].Severity)
	}
	if _, ok := byEP["1.1.3"]; ok {
		t.Errorf("PASS must not produce a finding")
	}
}

func TestParseKubeBench_Empty(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "e.json")
	_ = os.WriteFile(art, []byte(""), 0o600)
	f, err := parseKubeBench(art)
	if err != nil || f != nil {
		t.Errorf("empty artifact should yield no findings, got %v err=%v", f, err)
	}
}

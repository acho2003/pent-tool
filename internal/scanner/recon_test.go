package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconScopeKey(t *testing.T) {
	if got := reconScopeKey("example.com"); got != "recon:example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestIsBareHostInput(t *testing.T) {
	cases := map[string]bool{
		"http://localhost:3000/": true,
		"127.0.0.1":              true,
		"10.0.0.5:8080":          true,
		"example.com":            false,
		"sub.example.com":        false,
	}
	for in, want := range cases {
		if got := isBareHostInput(in); got != want {
			t.Errorf("isBareHostInput(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCandidateHostsStripsSchemeAndPort(t *testing.T) {
	got := candidateHosts("http://localhost:3000/")
	if len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("got %v, want [localhost]", got)
	}
}

func TestParseHttpxLive(t *testing.T) {
	jsonl := `{"url":"https://a.example.com","host":"a.example.com","port":443,"scheme":"https"}` + "\n" +
		`{"url":"http://b.example.com","host":"b.example.com","port":80,"scheme":"http"}` + "\n"
	dir := t.TempDir()
	p := filepath.Join(dir, "httpx.jsonl")
	if err := os.WriteFile(p, []byte(jsonl), 0o600); err != nil {
		t.Fatal(err)
	}
	res := parseHttpxLive(p)
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2", len(res))
	}
	if res[0].Host != "a.example.com" || !res[0].TLS || res[0].Scheme != "https" || res[0].Port != "443" {
		t.Fatalf("unexpected result[0]: %+v", res[0])
	}
	if res[1].TLS {
		t.Fatalf("result[1] TLS should be false for http scheme: %+v", res[1])
	}
}

func TestExecuteSpecOutputSubdirIsolatesPerHost(t *testing.T) {
	dir := t.TempDir()
	req := Request{Target: "example.com", ScanDir: dir}
	// A binary that cannot be found still gets its per-run log paths assigned
	// before the LookPath check, so this exercises path isolation without nmap.
	specA := commandSpec{path: "definitely-not-a-real-binary-xyz", outputSubdir: sanitizeHost("a.example.com")}
	specB := commandSpec{path: "definitely-not-a-real-binary-xyz", outputSubdir: sanitizeHost("b.example.com")}
	runA := executeSpec(context.Background(), "nmap", req, Config{}, specA, nil)
	runB := executeSpec(context.Background(), "nmap", req, Config{}, specB, nil)
	if runA.StdoutPath == runB.StdoutPath {
		t.Fatalf("per-host stdout paths collided: %q", runA.StdoutPath)
	}
	if runA.StderrPath == runB.StderrPath {
		t.Fatalf("per-host stderr paths collided: %q", runA.StderrPath)
	}
	if !strings.Contains(runA.StdoutPath, filepath.Join("nmap", "a.example.com")) {
		t.Fatalf("stdout path not nested under per-host dir: %q", runA.StdoutPath)
	}
	// Scanner name is preserved so ParseRun's `case "nmap"` still matches.
	if runA.Scanner != "nmap" {
		t.Fatalf("scanner name = %q, want nmap", runA.Scanner)
	}
}

func TestParseSubfinderHosts(t *testing.T) {
	jsonl := `{"host":"a.example.com"}` + "\n" + `{"host":"b.example.com"}` + "\n"
	dir := t.TempDir()
	p := filepath.Join(dir, "subfinder.jsonl")
	if err := os.WriteFile(p, []byte(jsonl), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts := parseSubfinderHosts(p)
	if len(hosts) != 2 || hosts[0] != "a.example.com" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestReconRunnerDescriptors(t *testing.T) {
	rs := []Runner{subfinderRunner{}, httpxRunner{}, nmapRunner{}}
	for _, r := range rs {
		d := r.Descriptor()
		if d.Phase != PhaseRecon {
			t.Errorf("%s phase = %q, want recon", d.Name, d.Phase)
		}
	}
}

func TestLoadReconScopesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok := LoadReconScopes(dir); ok {
		t.Fatal("missing file must report ok=false")
	}
	want := []Scope{{ID: "host:a.test", Kind: ScopeHost, Target: "a.test", Evidence: HostEvidence{LiveURLs: []string{"https://a.test"}, OpenPorts: []Port{{Number: 443, Protocol: "tcp", Service: "https"}}}}}
	saveReconScopes(dir, want)
	got, ok := LoadReconScopes(dir)
	if !ok || len(got) != 1 || got[0].ID != "host:a.test" || len(got[0].Evidence.OpenPorts) != 1 || got[0].Evidence.OpenPorts[0].Number != 443 {
		t.Fatalf("round trip = %#v, ok=%v", got, ok)
	}
}

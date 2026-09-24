package scanner

import (
	"os"
	"path/filepath"
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

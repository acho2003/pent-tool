package scanner

import "testing"

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

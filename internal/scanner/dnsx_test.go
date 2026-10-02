package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDNSXRunnerFailsClosedOnGuardedResolution(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "dnsx-fixture")
	script := "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"-o\" ]; then\n    shift\n    printf '%s\\n' '{\"host\":\"app.example.test\",\"a\":[\"127.0.0.1\"]}' > \"$1\"\n  fi\n  shift\ndone\n"
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DNSXPath: tool, ScopeGuard: func(_ string, resolved []string) (bool, string) {
		if len(resolved) == 1 && resolved[0] == "127.0.0.1" {
			return true, "loopback"
		}
		return false, ""
	}}
	run := (dnsxRunner{}).Run(context.Background(), Request{Target: "app.example.test", ScanDir: dir}, cfg, nil)
	if run.Status != "failed" || run.DNSResolution == nil || run.Reason == "" {
		t.Fatalf("unsafe DNS answer was accepted: %+v", run)
	}
}

func TestParseDNSXRetainsOnlyApprovedHostAndFlagsWildcard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.jsonl")
	data := "{\"host\":\"app.example.test\",\"a\":[\"192.0.2.5\",\"bad\"],\"aaaa\":[\"2001:db8::5\"],\"cname\":[\"edge.example.test\"]}\n" +
		"{\"host\":\"xalgorix-probe.app.example.test\",\"a\":[\"192.0.2.5\"]}\n" +
		"{\"host\":\"other.example.test\",\"a\":[\"127.0.0.1\"]}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseDNSX(path, "app.example.test", "xalgorix-probe.app.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.A) != 1 || got.A[0] != "192.0.2.5" || len(got.AAAA) != 1 || got.AAAA[0] != "2001:db8::5" || len(got.CNAME) != 1 || !got.Wildcard {
		t.Fatalf("unexpected DNS evidence: %+v", got)
	}
}

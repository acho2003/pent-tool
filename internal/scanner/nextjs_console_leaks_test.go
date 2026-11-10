package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserConsoleLeakDetection(t *testing.T) {
	req := Request{Target: "https://app.example.test/"}
	page := "https://app.example.test/dashboard"
	// A console dump mixing an AWS key, a JWT, an internal URL and a misused
	// NEXT_PUBLIC_ secret variable name.
	text := strings.Join([]string{
		`login response {"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJldmFsdWUx"}`,
		"aws key AKIAIOSFODNN7EXAMPLE",
		"calling http://10.0.0.5:8080/internal/api",
		"NEXT_PUBLIC_STRIPE_SECRET_KEY loaded",
	}, "\n")

	got := ruleIDs(browserConsoleLeakFindings(req, page, text, "ev"))
	for _, want := range []string{
		"browser-console-credential-aws-access-key",
		"browser-console-auth-token",
		"browser-console-internal-url",
		"browser-console-public-secret-var",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected console finding %s; got %v", want, keysOf(got))
		}
	}
	// Every finding must be a confirmed browser finding and must not leak the raw
	// secret, token or key material.
	for id, f := range got {
		if f.Scanner != "browser" || f.Confidence != "confirmed" {
			t.Errorf("%s has wrong scanner/confidence: %+v", id, f)
		}
		for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "eyJhbGciOiJIUzI1NiJ9", "c2lnbmF0dXJldmFsdWUx"} {
			if strings.Contains(f.Evidence, secret) || strings.Contains(f.Description, secret) {
				t.Fatalf("%s leaked secret material: %q", id, f.Evidence)
			}
		}
	}

	// A clean console produces nothing.
	if f := browserConsoleLeakFindings(req, page, "app ready\nuser logged in\nrendering 42 rows", "ev"); len(f) != 0 {
		t.Fatalf("clean console flagged: %+v", f)
	}
}

func TestParseBrowserAcceptsConsoleFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "browser.jsonl")
	finding := browserConsoleLeakFindings(Request{Target: "https://app.example.test/"},
		"https://app.example.test/", "token AKIAIOSFODNN7EXAMPLE", "ev")[0]
	row, _ := json.Marshal(map[string]any{"finding": finding})
	if err := os.WriteFile(path, append(row, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseBrowserAssetFindings(path)
	if err != nil {
		t.Fatalf("console finding rejected by browser parser: %v", err)
	}
	if len(parsed) != 1 || parsed[0].RuleID != finding.RuleID {
		t.Fatalf("round-trip mismatch: %+v", parsed)
	}
}

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestResolveSourceScopeFilesystem(t *testing.T) {
	dir := t.TempDir()
	req := Request{Artifact: Artifact{Kind: "filesystem", Ref: dir}, ScanDir: t.TempDir()}
	sc := resolveSourceScope(context.Background(), req, Config{}, nil)
	if sc.Kind != ScopeSource {
		t.Fatalf("kind = %q", sc.Kind)
	}
	if sc.Target != dir {
		t.Errorf("Target = %q, want %q", sc.Target, dir)
	}
}

func TestResolveSourceScopeNoSource(t *testing.T) {
	req := Request{Target: "https://example.com/", ScanDir: t.TempDir()}
	sc := resolveSourceScope(context.Background(), req, Config{}, nil)
	if sc.Kind != ScopeSource || sc.ID != sourceScopeID {
		t.Fatalf("unexpected scope %+v", sc)
	}
	if sc.Target != "" {
		t.Errorf("expected empty Target for unresolved source, got %q", sc.Target)
	}
}

func TestResolveSourceScopeReusesCheckout(t *testing.T) {
	scanDir := t.TempDir()
	dir := sourceCheckoutDir(scanDir)
	if err := mkGitDir(dir); err != nil { // helper: create dir + dir/.git
		t.Fatal(err)
	}
	req := Request{Target: "https://github.com/x/y.git", ScanDir: scanDir}
	sc := resolveSourceScope(context.Background(), req, Config{}, nil)
	if sc.Target != dir {
		t.Errorf("expected reused checkout %q, got %q", dir, sc.Target)
	}
}

func TestIsGitURL(t *testing.T) {
	cases := map[string]bool{
		"https://github.com/x/y.git": true,
		"git@github.com:x/y.git":     true,
		"git://example.com/x/y":      true,
		"https://example.com/":       false,
		"example.com":                false,
	}
	for in, want := range cases {
		if got := isGitURL(in); got != want {
			t.Errorf("isGitURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSourceScopePersistedByPipeline(t *testing.T) {
	scanDir, src := t.TempDir(), t.TempDir()
	if _, ok := LoadSourceScope(scanDir); ok {
		t.Fatal("no file yet must report ok=false")
	}
	p := &Pipeline{}
	p.Run(context.Background(), Request{Target: "example.test", ScanDir: scanDir, Artifact: Artifact{Kind: "filesystem", Ref: src}}, nil, nil)
	got, ok := LoadSourceScope(scanDir)
	if !ok || got.ID != "source:main" || got.Target != src || got.Source.Provenance != "provided:filesystem" {
		t.Fatalf("persisted source scope = %#v ok=%v", got, ok)
	}
}

func TestRedactCloneProvenance(t *testing.T) {
	cases := map[string]string{
		"clone:https://user:tok@github.com/a/b.git": "clone:https://github.com/a/b.git",
		"clone:https://github.com/a/b.git":          "clone:https://github.com/a/b.git",
		"clone:git@github.com:a/b.git":              "clone:git@github.com:a/b.git",
		"provided:filesystem":                       "provided:filesystem",
	}
	for in, want := range cases {
		if got := redactCloneProvenance(in); got != want {
			t.Errorf("redactCloneProvenance(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSaveSourceScopeRedactsCredentials(t *testing.T) {
	scanDir := t.TempDir()
	sc := Scope{ID: sourceScopeID, Kind: ScopeSource, Target: "/scans/x/source/checkout", Source: SourceRef{Path: "/scans/x/source/checkout", Provenance: "clone:https://user:tok@github.com/a/b.git"}}
	original := sc.Source.Provenance

	saveSourceScope(scanDir, sc)

	raw, err := os.ReadFile(sourceScopePath(scanDir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tok") || strings.Contains(string(raw), "user:") {
		t.Fatalf("persisted file still contains credentials: %s", raw)
	}
	got, ok := LoadSourceScope(scanDir)
	if !ok || got.ID != "source:main" || got.Source.Provenance != "clone:https://github.com/a/b.git" {
		t.Fatalf("loaded source scope = %#v ok=%v", got, ok)
	}
	if sc.Source.Provenance != original {
		t.Fatalf("caller's Scope was mutated: %q, want %q", sc.Source.Provenance, original)
	}
}

func mkGitDir(dir string) error {
	return mkdirAll(filepath.Join(dir, ".git"))
}

func mkdirAll(p string) error {
	return os.MkdirAll(p, 0o750)
}

func TestRedactURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://user:tok@h/a.git", "https://h/a.git"},
		{"https://:tok@h/a.git", "https://h/a.git"},
		{"https://h/a.git?token=abc#x", "https://h/a.git"},
		{"https://user:to%zz@h/a.git", "<redacted URL>"},     // unparseable: fail closed
		{"https:user:tok@h/a.git", "<redacted URL>"},         // opaque with userinfo: fail closed
		{"git@github.com:a/b.git", "git@github.com:a/b.git"}, // scp-style: no scheme
		{"https://h/a.git", "https://h/a.git"},
		{"https://H/a%2fb.git", "https://H/a%2fb.git"}, // nothing to strip: no normalization drift
	}
	for _, c := range cases {
		if got := RedactURL(c.in); got != c.want {
			t.Errorf("RedactURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := redactCloneProvenance("clone:https://user:to%zz@h/a.git"); got != "clone:<redacted URL>" {
		t.Errorf("unparseable clone URL must fail closed, got %q", got)
	}
}

func TestCloneCredentials(t *testing.T) {
	cases := []struct {
		url  string
		want []string
	}{
		{"https://user:tok123456@github.com/a/b.git", []string{"tok123456"}},
		{"https://ghp_abcdef123@github.com/a/b.git", []string{"ghp_abcdef123"}},
		{"https://user:to%2Fk9999@github.com/a/b.git", []string{"to/k9999", "to%2Fk9999"}},
		{"https://user:to%zz9999@github.com/a/b.git", []string{"to%zz9999"}}, // unparseable: raw form
		{"https://github.com/a/b.git", nil},
		{"git@github.com:a/b.git", nil},
		{"", nil},
	}
	for _, c := range cases {
		if got := cloneCredentials(c.url); !slices.Equal(got, c.want) {
			t.Errorf("cloneCredentials(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestCloneSecretsAreRedactedFromScannerOutput(t *testing.T) {
	repo := withCloneSecrets(Request{Target: "example.test", Artifact: Artifact{Kind: "repository", Ref: "https://user:tok123456@github.com/a/b.git"}})
	if got := secretValues(repo, Config{}); !slices.Contains(got, "tok123456") {
		t.Fatalf("repository artifact token missing from secrets: %q", got)
	}
	target := withCloneSecrets(Request{Target: "https://ghp_abcdef123@github.com/a/b.git"})
	// Per-scope requests replace Target (with a host or the checkout path); the
	// secret must survive that.
	scoped := target
	scoped.Target = "/scans/x/source/checkout"
	if got := redact("fatal: could not read https://ghp_abcdef123@github.com/a/b.git", secretValues(scoped, Config{})); strings.Contains(got, "ghp_abcdef123") {
		t.Fatalf("git-URL target token leaked into output: %q", got)
	}
	if plain := withCloneSecrets(Request{Target: "https://example.test"}); len(plain.Secrets) != 0 {
		t.Fatalf("non-credentialed request gained secrets: %q", plain.Secrets)
	}
}

func TestScrubCloneRemoteRemovesToken(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	const raw = "https://user:tok123456@github.com/a/b.git"
	for _, args := range [][]string{{"init", "-q", dir}, {"-C", dir, "remote", "add", "origin", raw}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	scrubCloneRemote(context.Background(), dir, raw)
	cfg, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "tok123456") || !strings.Contains(string(cfg), "https://github.com/a/b.git") {
		t.Fatalf(".git/config not scrubbed:\n%s", cfg)
	}
}

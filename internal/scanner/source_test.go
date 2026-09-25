package scanner

import (
	"context"
	"os"
	"path/filepath"
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

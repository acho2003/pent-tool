package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestVCSExposureDetectsGitAndSvnReadOnly(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/customer/app/.git/HEAD":
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		case "/customer/app/.git/config":
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.test/app.git\n"))
		case "/customer/app/.svn/wc.db":
			_, _ = w.Write([]byte("SQLite format 3\x00rest-of-db"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target := server.URL + "/customer/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (vcsExposureRunner{}).Run(context.Background(), Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	for _, got := range paths {
		if !strings.HasPrefix(got, "GET ") {
			t.Fatalf("unsafe method emitted: %s", got)
		}
		if strings.HasPrefix(got, "GET /") && !strings.HasPrefix(got, "GET /customer/app") {
			t.Fatalf("request escaped path scope: %s", got)
		}
	}
	data, err := os.ReadFile(run.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, "source_control_exposed") < 3 {
		t.Fatalf("expected git HEAD, git config and svn findings, got %s", text)
	}
	// The remote URL (which can carry credentials) must not be copied verbatim.
	if strings.Contains(text, "example.test/app.git") {
		t.Fatalf("a remote URL leaked into the findings artifact: %s", text)
	}
}

func TestVCSExposureIgnoresSpaCatchAll(t *testing.T) {
	// A single-page app answers every path, including /.git/HEAD, with 200 HTML.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html><body>app</body></html>"))
	}))
	defer server.Close()

	target := server.URL + "/customer/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (vcsExposureRunner{}).Run(context.Background(), Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	data, _ := os.ReadFile(run.ArtifactPath)
	if len(strings.TrimSpace(string(data))) != 0 {
		t.Fatalf("SPA catch-all HTML was misreported as source-control exposure: %s", data)
	}
}

func TestVCSClassifierRequiresMetadataSignature(t *testing.T) {
	ok := &http.Response{StatusCode: 200, Header: http.Header{}}
	if v := classifyVCS(exposureCheck{ID: "git-head"}, ok, []byte("0123456789abcdef0123456789abcdef01234567\n")); v.Severity != "high" {
		t.Fatalf("raw git HEAD sha not detected: %+v", v)
	}
	// A 200 that is not a git file (e.g. JSON error) is not an exposure.
	if v := classifyVCS(exposureCheck{ID: "git-config"}, ok, []byte(`{"error":"not found"}`)); v.Classification != "" {
		t.Fatalf("non-git body flagged: %+v", v)
	}
}

func TestVCSCatalogIsDeterministic(t *testing.T) {
	if vcsCatalogVersion != "vcs-exposure-v1" {
		t.Fatalf("unexpected catalog version: %s", vcsCatalogVersion)
	}
	seen := map[string]bool{}
	for _, check := range vcsCatalog {
		if check.ID == "" || check.Path == "" || seen[check.ID] {
			t.Fatalf("catalog contains an invalid or duplicate entry: %+v", check)
		}
		seen[check.ID] = true
	}
}

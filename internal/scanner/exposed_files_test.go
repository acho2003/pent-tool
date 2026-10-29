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

func TestExposedFilesDetectsSecretsWithoutLeakingThem(t *testing.T) {
	const awsSecret = "AKIAIOSFODNN7EXAMPLE"
	const envSecret = "super-secret-app-key"
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/customer/app/.env":
			_, _ = w.Write([]byte("APP_ENV=production\nAPP_KEY=" + envSecret + "\nDB_PASSWORD=hunter2\n"))
		case "/customer/app/.aws/credentials":
			_, _ = w.Write([]byte("[default]\naws_access_key_id = " + awsSecret + "\naws_secret_access_key = wJalrXUtn\n"))
		case "/customer/app/.ssh/id_rsa":
			_, _ = w.Write([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target := server.URL + "/customer/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (exposedFilesRunner{}).Run(context.Background(), Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
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
	if strings.Count(text, "sensitive_file_exposed") < 3 {
		t.Fatalf("expected .env, aws and ssh-key findings, got %s", text)
	}
	// The whole point: detect exposure, never copy the secret into the artifact.
	for _, secret := range []string{awsSecret, envSecret, "hunter2", "wJalrXUtn", "b3BlbnNzaC1rZXk"} {
		if strings.Contains(text, secret) {
			t.Fatalf("a secret value leaked into the findings artifact: %q in %s", secret, text)
		}
	}
}

func TestExposedFilesIgnoresCatchAllAndEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every path answers 200 HTML (SPA) — nothing is a real secret file.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html><body>not here</body></html>"))
	}))
	defer server.Close()

	target := server.URL + "/customer/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (exposedFilesRunner{}).Run(context.Background(), Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	data, _ := os.ReadFile(run.ArtifactPath)
	if len(strings.TrimSpace(string(data))) != 0 {
		t.Fatalf("SPA catch-all misreported as exposed files: %s", data)
	}
}

func TestExposedFilesClassifierRequiresSignature(t *testing.T) {
	ok := &http.Response{StatusCode: 200, Header: http.Header{}}
	// A single stray KEY=value line is not enough to call a body a .env file.
	if v := classifyExposedFile(exposureCheck{ID: "dotenv"}, ok, []byte("GET=request\n")); v.Classification != "" {
		t.Fatalf("one-line body flagged as .env: %+v", v)
	}
	if v := classifyExposedFile(exposureCheck{ID: "dotenv"}, ok, []byte("APP_ENV=prod\nAPP_KEY=abc\n")); v.Severity != "high" {
		t.Fatalf("real .env not detected: %+v", v)
	}
}

func TestExposedFilesCatalogIsDeterministic(t *testing.T) {
	if exposedFilesCatalogVersion != "exposed-files-v1" {
		t.Fatalf("unexpected catalog version: %s", exposedFilesCatalogVersion)
	}
	seen := map[string]bool{}
	for _, check := range exposedFilesCatalog {
		if check.ID == "" || check.Path == "" || seen[check.ID] {
			t.Fatalf("catalog contains an invalid or duplicate entry: %+v", check)
		}
		seen[check.ID] = true
	}
}

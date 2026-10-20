package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestKubeExposureRunnerIsReadOnlyAndScopeBound(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/customer/app/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"gitVersion":"v1.30.0"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target := server.URL + "/customer/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	dir := t.TempDir()
	run := (kubeExposureRunner{}).Run(context.Background(), Request{Target: target, ScanDir: dir, Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 20, 0)}, nil)
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
	if !strings.Contains(string(data), "confirmed_exposure") {
		t.Fatalf("expected confirmed API evidence, got %s", data)
	}
}

func TestKubeExposureCatalogIsDeterministic(t *testing.T) {
	if kubeExposureCatalogVersion != "kube-exposure-v2" || len(kubeExposureCatalog) != 8 {
		t.Fatalf("unexpected catalog version or size: %s/%d", kubeExposureCatalogVersion, len(kubeExposureCatalog))
	}
	seen := map[string]bool{}
	for _, check := range kubeExposureCatalog {
		if check.ID == "" || check.Path == "" || seen[check.ID] {
			t.Fatalf("catalog contains an invalid or duplicate entry: %+v", check)
		}
		seen[check.ID] = true
	}
}

func TestKubeRequestErrorKeepsUsefulNetworkCause(t *testing.T) {
	for _, test := range []struct {
		input, want string
	}{
		{"Get \"https://missing.invalid\": dial tcp: lookup missing.invalid: no such host", "no such host"},
		{"Get \"https://target.invalid\": x509: certificate signed by unknown authority", "x509: certificate signed by unknown authority"},
		{"redirect refused: /outside is not approved", "redirect refused"},
	} {
		if got := kubeRequestError(fmt.Errorf("%s", test.input)); !strings.Contains(got, test.want) {
			t.Errorf("kubeRequestError(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

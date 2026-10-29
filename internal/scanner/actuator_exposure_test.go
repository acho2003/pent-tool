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

func TestActuatorExposureDetectsManagementSurfaceReadOnly(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/customer/app/actuator":
			w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
			_, _ = w.Write([]byte(`{"_links":{"self":{"href":"/actuator"},"env":{"href":"/actuator/env"},"heapdump":{"href":"/actuator/heapdump"}}}`))
		case "/customer/app/actuator/env":
			w.Header().Set("Content-Type", "application/json")
			// A real env body would carry secret values; the adapter must flag the
			// exposure without copying any of them into its artifact.
			_, _ = w.Write([]byte(`{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment","properties":{"DB_PASSWORD":{"value":"s3cr3t-should-not-leak"}}}]}`))
		case "/customer/app/actuator/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"UP"}`))
		case "/customer/app/actuator/heapdump":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("JAVA PROFILE 1.0.2\x00\x00binary-heap"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target := server.URL + "/customer/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (actuatorExposureRunner{}).Run(context.Background(), Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 50, 0)}, nil)
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
	for _, want := range []string{"configuration_disclosure", "sensitive_artifact_exposed", "management_surface_exposed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected classification %q in findings, got %s", want, text)
		}
	}
	if !strings.Contains(text, `"severity":"high"`) {
		t.Fatalf("env/heapdump exposure should be high severity, got %s", text)
	}
	if strings.Contains(text, "s3cr3t-should-not-leak") || strings.Contains(text, "DB_PASSWORD") {
		t.Fatalf("a secret value or key leaked into the findings artifact: %s", text)
	}
}

func TestActuatorClassifierIgnoresUnrelatedAndSecuredResponses(t *testing.T) {
	check := exposureCheck{ID: "actuator-metrics", Path: "/actuator/metrics"}
	// Plain JSON API that is not Actuator-shaped must not be flagged.
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}}
	if v := classifyActuator(check, resp, []byte(`{"result":"ok","data":[1,2,3]}`)); v.Classification != "" {
		t.Fatalf("non-actuator JSON was flagged: %+v", v)
	}
	// A secured endpoint (401/403) is not an exposure.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		secured := &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/vnd.spring-boot.actuator.v3+json"}}}
		if v := classifyActuator(exposureCheck{ID: "actuator-env"}, secured, []byte(`{"propertySources":[]}`)); v.Classification != "" {
			t.Fatalf("HTTP %d actuator response was flagged as exposure: %+v", code, v)
		}
	}
	// A genuine Actuator metrics body (carries "names") is flagged.
	if v := classifyActuator(check, resp, []byte(`{"names":["jvm.memory.used"]}`)); v.Classification != "management_surface_exposed" {
		t.Fatalf("actuator metrics endpoint not detected: %+v", v)
	}
}

func TestActuatorCatalogIsDeterministic(t *testing.T) {
	if actuatorCatalogVersion != "actuator-v1" {
		t.Fatalf("unexpected catalog version: %s", actuatorCatalogVersion)
	}
	seen := map[string]bool{}
	for _, check := range actuatorCatalog {
		if check.ID == "" || check.Path == "" || seen[check.ID] {
			t.Fatalf("catalog contains an invalid or duplicate entry: %+v", check)
		}
		seen[check.ID] = true
	}
}

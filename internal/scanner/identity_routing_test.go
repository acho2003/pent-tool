package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestNamedIdentityJobsArePreviewedWithIndependentDependencies(t *testing.T) {
	cfg := assessment.AssessmentConfig{WorkflowVersion: "unified-v1", Access: []assessment.AccessBinding{
		{Kind: assessment.AccessBearerToken, Identity: "admin", Role: "administrator", TargetIDs: []string{"app"}},
		{Kind: assessment.AccessBearerToken, Identity: "reader", Role: "read-only", TargetIDs: []string{"app"}},
	}}
	jobs := []PlanJob{{ID: "auth", Scanner: "auth", TargetID: "app", Variant: "auth", State: PlanSelected}, {ID: "crawl", Scanner: "katana", TargetID: "app", Variant: "katana", State: PlanSelected}, {ID: "zap", Scanner: "zap", TargetID: "app", Variant: "zap", State: PlanSelected}, {ID: "nuclei", Scanner: "nuclei", TargetID: "app", Variant: "nuclei", State: PlanSelected}, {ID: "writes", Scanner: "apiwrites", TargetID: "app", Variant: "apiwrites", State: PlanSelected}}
	expanded := expandIdentityJobs(cfg, jobs)
	assignStages(expanded)
	if len(expanded) != 8 {
		t.Fatalf("unapproved or missing job expansion: %+v", expanded)
	}
	roleID := AuthenticationContextID("app", "reader")
	for _, job := range expanded {
		if job.AuthContextID != "" {
			if job.AuthContextID != roleID || job.AuthIdentity != "reader" || job.AuthRole != "read-only" {
				t.Fatalf("incorrect identity: %+v", job)
			}
			for _, dependency := range job.Dependencies {
				if !strings.Contains(dependency, roleID) {
					t.Fatalf("role depends on another role: %+v", job)
				}
			}
		}
	}
	cfg.WorkflowVersion = ""
	if len(expandIdentityJobs(cfg, jobs)) != len(jobs) {
		t.Fatal("legacy executor inventory changed")
	}
}

func TestRoleRoutingKeepsSelectionReceiptsAndCredentialsSeparate(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", Port: 443}})
	roleID := AuthenticationContextID("app", "reader")
	surface := &AttackSurface{Scope: "app:app", Endpoints: []AttackSurfaceEndpoint{
		{ID: "primary", URL: "https://app.test/?q=1", Method: "GET", State: EndpointStateInScope, AuthContextID: inventoryID("app:app", "target-bound"), HasParameters: true},
		{ID: "reader", URL: "https://app.test/?q=1", Method: "GET", State: EndpointStateInScope, AuthContextID: roleID, HasParameters: true},
		{ID: "anonymous", URL: "https://app.test/?q=1", Method: "GET", State: EndpointStateInScope, HasParameters: true},
	}}
	targets := dispatchTargetsWithPolicy(surface, "nuclei", 100, &scope, nil, true, roleID)
	req := Request{AuthContextID: roleID, TargetAuth: "Authorization: Bearer reader-secret", EndpointTargets: targets}
	inputs := BuildScannerInputs(surface, req, "nuclei")
	selected := []string{}
	for _, input := range inputs {
		if input.Selected {
			selected = append(selected, input.EndpointID)
		}
	}
	if !slices.Equal(selected, []string{"reader"}) {
		t.Fatalf("cross-role selection: %+v", inputs)
	}
	outgoing, _ := http.NewRequest("GET", targets[0], nil)
	outgoing.Header.Set("Authorization", "Bearer reader-secret")
	for _, input := range inputs {
		matched := gatewayInputAuthenticationMatches(input, outgoing, req.TargetAuth, true, roleID)
		if matched != (input.EndpointID == "reader") {
			t.Fatalf("wrong receipt attribution: %+v", input)
		}
	}
	CompleteEndpointCoverage(surface, "nuclei", Run{Status: "completed", AttemptID: "reader-attempt"})
	for _, endpoint := range surface.Endpoints {
		if endpoint.ID != "reader" && len(endpoint.ScannerCoverage) > 0 {
			t.Fatalf("other context coverage overwritten: %+v", endpoint)
		}
	}
}

func TestExpiredNamedIdentityNeverFallsBackToPrimary(t *testing.T) {
	primary := AuthContext{ID: AuthenticationContextID("app", "admin"), TargetID: "app", State: assessment.StateVerified, Headers: []string{"Authorization: Bearer admin-secret"}, Refresh: func(context.Context, []string) ([]string, error) { t.Fatal("primary verifier used"); return nil, nil }}
	reader := AuthContext{ID: AuthenticationContextID("app", "reader"), TargetID: "app", State: assessment.StateVerified, Headers: []string{"Authorization: Bearer reader-secret"}, Refresh: func(context.Context, []string) ([]string, error) { return nil, errors.New("expired") }}
	pipeline := &Pipeline{Config: Config{AssessmentAuthContexts: []AuthContext{primary, reader}}}
	auth, err := pipeline.refreshIdentity(t.Context(), "app", reader.ID)
	if err == nil || auth.State != assessment.StateExpired {
		t.Fatal("expired identity accepted")
	}
	if _, err = pipeline.refreshIdentity(t.Context(), "other", primary.ID); err == nil {
		t.Fatal("credential crossed target binding")
	}
}

func TestNamedIdentityGatewayRecordsOnlyItsOwnNativeReceipt(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer reader-fixture-secret" {
			t.Error("wrong identity reached local fixture")
		}
		w.Write([]byte("reader resource"))
	}))
	defer target.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", target.URL)
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	reader := AuthenticationContextID("app", "reader")
	req := Request{Target: target.URL, AppScope: &scope, ScanDir: t.TempDir(), AuthContextID: reader, TargetAuth: "Authorization: Bearer reader-fixture-secret", InputRequests: []ScannerRequestInput{
		{EndpointID: "reader", AuthContextID: reader, InventoryScope: "app:app", URL: target.URL + "/", Method: "GET", Selected: true},
		{EndpointID: "admin", AuthContextID: AuthenticationContextID("app", "admin"), InventoryScope: "app:app", URL: target.URL + "/", Method: "GET", Selected: true},
		{EndpointID: "anonymous", InventoryScope: "app:app", URL: target.URL + "/", Method: "GET", Selected: true},
	}}
	gateway, err := NewRecordingGateway(t.Context(), req, Config{}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	proxy, _ := url.Parse(gateway.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if err = gateway.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := ReadCoverageEvents(gateway.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	observed := false
	for _, event := range events {
		if event.Kind == "observed" {
			observed = true
			if !slices.Equal(event.EndpointIDs, []string{"reader"}) {
				t.Fatalf("native response attributed to other roles: %+v", event)
			}
		}
	}
	if !observed {
		t.Fatal("no native receipt")
	}
}

func TestExecutorForwardsNamedIdentityWithoutPrimarySubstitution(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	id := AuthenticationContextID("app", "reader")
	runner := &resourceJobRunner{name: "nuclei"}
	verified := 0
	pipeline := &Pipeline{Runners: []Runner{runner}, Config: Config{AssessmentAuthHeaders: map[string][]string{"app": {"Authorization: Bearer admin-secret"}}, AssessmentAuthContexts: []AuthContext{{ID: id, TargetID: "app", Identity: "reader", State: assessment.StateVerified, Headers: []string{"Authorization: Bearer reader-secret"}, Refresh: func(_ context.Context, headers []string) ([]string, error) { verified++; return headers, nil }}}}}
	plan := AssessmentPlan{Fingerprint: "sha256:role-executor", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1"}, Jobs: []PlanJob{{ID: "reader-nuclei", Scanner: "nuclei", Variant: "nuclei:reader", TargetID: "app", Target: "https://local-fixture.invalid/", State: PlanSelected, AuthContextID: id, AuthIdentity: "reader", Stage: StageTemplates}}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if len(runs) != 1 || runner.calls != 1 || runner.authHeader != "Authorization: Bearer reader-secret" || runs[0].AuthContextID != id || runs[0].AuthIdentity != "reader" || verified < 2 {
		t.Fatalf("wrong identity reached adapter: %+v header %q checks %d", runs, runner.authHeader, verified)
	}
}

func TestRoleSchemaSeedsPreserveUnobservedAndAuthorizedDisposition(t *testing.T) {
	id := AuthenticationContextID("app", "reader")
	surface := &AttackSurface{Scope: "app:app", Target: "https://app.test/", Endpoints: []AttackSurfaceEndpoint{
		{ID: "read", URL: "https://app.test/items?id=existing", Method: "GET", ObservationKind: "schema", State: EndpointStateInScope, Kind: "api", HasParameters: true},
		{ID: "write", URL: "https://app.test/items", Method: "POST", ObservationKind: "schema", State: EndpointStateInScope, Kind: "api"},
		{ID: "unresolved", URL: "https://app.test/items/{id}", Method: "GET", ObservationKind: "schema", State: EndpointStateUnmaterialized, Kind: "api"},
		{ID: "external", URL: "https://alias.test/items", Method: "GET", ObservationKind: "schema", State: EndpointStateInScope, Kind: "api"},
	}}
	contexts := []AuthContext{{ID: id, TargetID: "app", Identity: "reader", State: assessment.StateVerified}}
	addIdentitySchemaSeeds(surface, "app", contexts)
	addIdentitySchemaSeeds(surface, "app", contexts)
	if len(surface.Endpoints) != 5 {
		t.Fatalf("invented or duplicate request variants: %+v", surface.Endpoints)
	}
	role := surface.Endpoints[4]
	if role.AuthContextID != id || role.URL != surface.Endpoints[0].URL || role.ObservedWithAuth || role.RequiresAuth != nil || role.ObservationKind != "schema" {
		t.Fatalf("schema seed claimed observed auth: %+v", role)
	}
}

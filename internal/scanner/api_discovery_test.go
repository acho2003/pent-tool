package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGraphQLUploadSeparatesQueriesMissingInputsAndMutations(t *testing.T) {
	endpoints, err := ParseAPIDefinition([]byte(`type Query { ping: String user(id: ID!): User } type User { id: ID! } type Mutation { erase(id: ID!): Boolean }`), "https://app.test/")
	if err != nil || len(endpoints) != 3 {
		t.Fatalf("%+v %v", endpoints, err)
	}
	for _, e := range endpoints {
		switch e.OperationID {
		case "query ping":
			if !e.Eligible || e.RequestURL == "" {
				t.Fatal(e)
			}
		case "query user":
			if e.Eligible || len(e.MissingInputs) != 1 {
				t.Fatal(e)
			}
		case "mutation erase":
			if e.Eligible || e.Method != "POST" {
				t.Fatal(e)
			}
		}
	}
}
func TestDiscoverAPIsValidatesSchemasAndDoesNotFollowExternalRedirect(t *testing.T) {
	outsideHits := 0
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits++ }))
	defer outside.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Write([]byte(`{"openapi":"3.1.0","paths":{"/api/ping":{"get":{}},"/api/delete":{"post":{}}}}`))
		case "/swagger.json":
			http.Redirect(w, r, outside.URL, 302)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	surface := NewSeedAttackSurface("app", server.URL)
	endpoints := DiscoverAPIs(t.Context(), Request{Target: server.URL, AppScope: &scope, ScanDir: t.TempDir()}, Config{}, surface)
	if outsideHits != 0 || len(endpoints) != 2 || len(surface.Definitions) != 1 {
		t.Fatalf("hits=%d endpoints=%+v definitions=%+v", outsideHits, endpoints, surface.Definitions)
	}
}

func TestHistoricalMaterializedGraphQLWithoutReplayStaysUnresolved(t *testing.T) {
	endpoints, err := ParseAPIDefinition([]byte(`type Query { ping: String }`), "https://app.test/graphql")
	if err != nil {
		t.Fatal(err)
	}
	endpoints[0].RequestURL = ""
	surface := NewSeedAttackSurface("app:test", "https://app.test/")
	MergeOpenAPIEndpointsScoped(surface, "https://app.test/", endpoints, nil)
	for _, ep := range surface.Endpoints {
		if ep.Path == "/graphql" && ep.State != EndpointStateUnmaterialized {
			t.Fatal("historical request details were invented", ep)
		}
	}
}

func TestSchemaExternalServersStayApprovalCandidates(t *testing.T) {
	origin, _ := assessment.ParseApprovedOrigin("app", "https://app.test/")
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	surface := NewSeedAttackSurface("app:app", "https://app.test/")
	endpoints := []APIEndpoint{{DefinitionID: "schema", Source: "openapi", Method: "GET", Path: "/ping", Origin: "https://app.test", Eligible: true, Resolved: true, SpecServers: []string{"https://external.test/api/"}}}
	MergeOpenAPIEndpointsScoped(surface, "https://app.test/", endpoints, &scope)
	preview := BuildDiscoveryPreview(AssessmentPlan{Fingerprint: "plan", Config: assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/"}}}}, nil, []AttackSurface{*surface})
	if len(preview.Candidates) != 1 || preview.Candidates[0].Value != "https://external.test/api/" {
		t.Fatal(preview)
	}
	for _, ep := range surface.Endpoints {
		if ep.URL == "https://external.test/api/ping" {
			t.Fatal("schema server expanded live inventory")
		}
	}
}

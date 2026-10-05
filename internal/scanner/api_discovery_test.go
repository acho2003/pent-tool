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

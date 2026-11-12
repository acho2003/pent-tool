package scanner

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// placeholderSpec mirrors the shapes found in a real NestJS common service:
// optional pagination/sort/filter query parameters, an enum behind a $ref,
// numeric defaults, a parameter-level example and a UUID filter.
const placeholderSpec = `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
 "components":{"schemas":{"Order":{"type":"string","enum":["ASC","DESC"]}}},
 "paths":{
  "/common/genders":{
   "get":{"operationId":"listGenders","parameters":[
    {"name":"order","in":"query","required":false,"schema":{"$ref":"#/components/schemas/Order"}},
    {"name":"page","in":"query","required":false,"schema":{"type":"number","default":1}},
    {"name":"take","in":"query","required":false,"schema":{"type":"number","default":10}},
    {"name":"q","in":"query","required":false,"schema":{"type":"string"}},
    {"name":"sl_no","in":"query","example":"01","schema":{"type":"string","example":"99"}},
    {"name":"active","in":"query","schema":{"type":"boolean"}},
    {"name":"category_id","in":"query","schema":{"type":"string","format":"uuid"}},
    {"name":"filter","in":"query","schema":{"type":"object"}}
   ]},
   "post":{"operationId":"createGender","parameters":[{"name":"q","in":"query","schema":{"type":"string"}}]}
  },
  "/common/genders/{id}":{"get":{"operationId":"getGender","parameters":[
   {"name":"id","in":"path","required":true,"schema":{"type":"string"}},
   {"name":"q","in":"query","schema":{"type":"string"}}
  ]}}
 }}`

func parsePlaceholderSpec(t *testing.T, origin string) []APIEndpoint {
	t.Helper()
	endpoints, err := ParseOpenAPI([]byte(placeholderSpec), origin)
	if err != nil {
		t.Fatal(err)
	}
	return endpoints
}

func endpointByOperation(endpoints []APIEndpoint, id string) APIEndpoint {
	for _, endpoint := range endpoints {
		if endpoint.OperationID == id {
			return endpoint
		}
	}
	return APIEndpoint{}
}

func TestOpenAPIQueryPlaceholderPrecedence(t *testing.T) {
	list := endpointByOperation(parsePlaceholderSpec(t, "https://app.test"), "listGenders")
	got := map[string]string{}
	for _, parameter := range list.Parameters {
		if parameter.Location == "query" {
			got[parameter.Name] = parameter.Placeholder
		}
	}
	want := map[string]string{
		"order":       "ASC",                                  // first enum value, resolved through $ref
		"page":        "1",                                    // schema default
		"take":        "10",                                   // schema default
		"q":           "test",                                 // plain string
		"sl_no":       "01",                                   // parameter example wins over schema example
		"active":      "true",                                 // boolean
		"category_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", // uuid format
		"filter":      "",                                     // objects get no placeholder
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("placeholder for %s = %q, want %q", name, got[name], value)
		}
	}
}

func TestInventorySeedsOptionalQueryPlaceholdersForReadOnlyOperations(t *testing.T) {
	endpoints := parsePlaceholderSpec(t, "https://app.test")
	surface := NewSeedAttackSurface("app:test", "https://app.test/")
	MergeOpenAPIEndpointsScoped(surface, "https://app.test/", endpoints, nil)

	var list, post *AttackSurfaceEndpoint
	for i := range surface.Endpoints {
		ep := &surface.Endpoints[i]
		if ep.Path == "/common/genders" && ep.Method == "GET" {
			list = ep
		}
		if ep.Path == "/common/genders" && ep.Method == "POST" {
			post = ep
		}
		if strings.Contains(ep.URL, "/common/genders/") && strings.Contains(ep.URL, "?") {
			t.Fatalf("unmaterialized operation received a query string: %s", ep.URL)
		}
	}
	if list == nil {
		t.Fatal("GET /common/genders missing from inventory")
	}
	parsed, err := url.Parse(list.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	for name, value := range map[string]string{"order": "ASC", "page": "1", "take": "10", "q": "test", "sl_no": "01", "active": "true", "category_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"} {
		if query.Get(name) != value {
			t.Errorf("seeded %s=%q, want %q (url %s)", name, query.Get(name), value, list.URL)
		}
	}
	if query.Has("filter") {
		t.Errorf("object parameter must not be seeded: %s", list.URL)
	}
	labelled := false
	for _, provenance := range list.Provenance {
		if provenance.Tool == "openapi-placeholder" && strings.Contains(provenance.Source, "order") && strings.Contains(provenance.Source, "take") {
			labelled = true
		}
	}
	if !labelled {
		t.Errorf("placeholder values must be labelled in provenance, got %+v", list.Provenance)
	}
	if post != nil && strings.Contains(post.URL, "?") {
		t.Errorf("state-changing operation received placeholder query: %s", post.URL)
	}
}

func TestSuppliedQueryValuesWinOverPlaceholders(t *testing.T) {
	endpoints := parsePlaceholderSpec(t, "https://app.test")
	inputs := []assessment.APIOperationInput{{DefinitionID: "def", OperationID: "listGenders", Query: map[string]string{"q": "supplied"}}}
	endpoints = MaterializeOpenAPIOperations(endpoints, "def", "https://app.test/", inputs)
	list := endpointByOperation(endpoints, "listGenders")
	raw, filled, err := operationRequestURL("https://app.test/", list)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(raw)
	if parsed.Query().Get("q") != "supplied" || parsed.Query().Get("take") != "10" {
		t.Fatalf("supplied value lost or placeholders missing: %s", raw)
	}
	for _, name := range filled {
		if name == "q" {
			t.Fatalf("supplied parameter reported as a placeholder: %v", filled)
		}
	}
	again, filledAgain, _ := operationRequestURL("https://app.test/", APIEndpoint{Method: list.Method, Path: list.Path, Source: list.Source, Resolved: true, Eligible: true, RequestURL: raw, Parameters: list.Parameters})
	if again != raw || len(filledAgain) != 0 {
		t.Fatalf("placeholder application must be idempotent: %s %v", again, filledAgain)
	}
}

func TestHarvestedOperationsKeepQueryPlaceholders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/common/genders" {
			w.Write([]byte(`{"data":[{"id":"g-1"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	endpoints := MaterializeOpenAPIOperations(parsePlaceholderSpec(t, server.URL), "def", server.URL, nil)
	origin, _ := assessment.ParseApprovedOrigin("svc", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	harvested := HarvestPathValues(t.Context(), Request{Target: server.URL, AppScope: &scope}, Config{}, server.URL, endpoints)
	one := endpointByOperation(harvested, "getGender")
	if one.RequestURL != server.URL+"/common/genders/g-1" {
		t.Fatalf("path value not harvested: %+v", one)
	}
	raw, filled, err := operationRequestURL(server.URL, one)
	if err != nil || !strings.HasSuffix(raw, "/common/genders/g-1?q=test") || len(filled) != 1 {
		t.Fatalf("harvested operation lost its query parameters: %s %v %v", raw, filled, err)
	}
}

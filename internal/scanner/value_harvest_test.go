package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const harvestSpec = `{"openapi":"3.0.0","info":{"title":"common","version":"1"},"paths":{
 "/common/villages/all":{"get":{"operationId":"listVillages"}},
 "/common/villages/{id}":{"get":{"operationId":"getVillage","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]},
                          "delete":{"operationId":"deleteVillage","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}},
 "/common/gewogs/all":{"get":{"operationId":"listGewogs"}},
 "/common/chiwogs/by-gewog/{gewogId}":{"get":{"operationId":"chiwogsByGewog","parameters":[{"name":"gewogId","in":"path","required":true,"schema":{"type":"integer"}}]}},
 "/common/operators/check/{cidNo}":{"get":{"operationId":"checkOperator","parameters":[{"name":"cidNo","in":"path","required":true,"schema":{"type":"string"}}]}}
}}`

func TestHarvestPathValuesFromListResponses(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/common/villages/all":
			w.Write([]byte(`{"statusCode":200,"data":[{"id":"v-7","name":"Thimphu"},{"id":"v-8"}]}`))
		case "/common/gewogs/all":
			w.Write([]byte(`[{"id":12,"gewogCode":"G01"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	endpoints, err := ParseOpenAPI([]byte(harvestSpec), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoints = MaterializeOpenAPIOperations(endpoints, "def", server.URL, nil)
	origin, _ := assessment.ParseApprovedOrigin("svc", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	harvested := HarvestPathValues(t.Context(), Request{Target: server.URL, AppScope: &scope}, Config{}, server.URL, endpoints)
	byOperation := map[string]APIEndpoint{}
	for _, endpoint := range harvested {
		byOperation[endpoint.OperationID] = endpoint
	}
	village, ok := byOperation["getVillage"]
	if !ok || village.RequestURL != server.URL+"/common/villages/v-7" || !village.Resolved || !village.Eligible || village.Path != "/common/villages/{id}" || !strings.Contains(village.ValueSource, "/common/villages/all") {
		t.Fatalf("village not harvested: %+v", village)
	}
	chiwogs, ok := byOperation["chiwogsByGewog"]
	if !ok || chiwogs.RequestURL != server.URL+"/common/chiwogs/by-gewog/12" || !strings.Contains(chiwogs.ValueSource, "/common/gewogs/all") {
		t.Fatalf("foreign key not harvested from the gewogs collection: %+v", chiwogs)
	}
	if _, ok := byOperation["checkOperator"]; ok {
		t.Fatal("an operation without an observed value was materialized")
	}
	if _, ok := byOperation["deleteVillage"]; ok {
		t.Fatal("a state-changing operation was materialized")
	}
	for _, request := range requests {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("harvesting sent a non-GET request: %s", request)
		}
	}
	if len(requests) > 3 {
		t.Fatalf("list responses were not cached: %v", requests)
	}
}

func TestHarvestRespectsScopeAndValueSafety(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`[{"id":"../../etc/passwd"},{"id":"a/b"}]`))
	}))
	defer server.Close()
	endpoints := MaterializeOpenAPIOperations([]APIEndpoint{
		{Method: "GET", Path: "/items", Source: "openapi", Resolved: true, Eligible: true},
		{Method: "GET", Path: "/items/{id}", Source: "openapi", Resolved: false, Reason: "path parameters have no supplied values"},
	}, "def", server.URL, nil)
	origin, _ := assessment.ParseApprovedOrigin("svc", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	if harvested := HarvestPathValues(t.Context(), Request{Target: server.URL, AppScope: &scope}, Config{}, server.URL, endpoints); len(harvested) != 0 {
		t.Fatalf("unsafe path values were used: %+v", harvested)
	}
	excluded := assessment.NewAppScope([]assessment.ApprovedOrigin{origin}, assessment.Exclusion{Method: "*", PathPattern: "/items", Reason: "operator exclusion"})
	hits = 0
	HarvestPathValues(t.Context(), Request{Target: server.URL, AppScope: &excluded}, Config{}, server.URL, endpoints)
	if hits != 0 {
		t.Fatal("an excluded list operation was fetched")
	}
}

func TestHarvestKeysAndCandidateOrdering(t *testing.T) {
	if keys := harvestKeys("gewogId"); keys[0] != "gewogId" || keys[1] != "id" {
		t.Fatalf("keys %v", keys)
	}
	lists := []harvestList{{path: "/common/gewogs/all"}, {path: "/common/chiwogs"}, {path: "/common/cm-navigation"}}
	if got := candidateLists("/common/chiwogs/by-gewog/{gewogId}", "gewogId", lists); len(got) == 0 || got[0].path != "/common/gewogs/all" {
		t.Fatalf("gewogs collection not preferred: %+v", got)
	}
	if got := candidateLists("/common/cm-sub-links/navigation/{navigationId}", "navigationId", lists); len(got) == 0 || got[0].path != "/common/cm-navigation" {
		t.Fatalf("prefixed collection name not matched: %+v", got)
	}
	if got := candidateLists("/common/chiwogs/{id}", "id", lists); len(got) != 1 || got[0].path != "/common/chiwogs" {
		t.Fatalf("own collection not chosen for {id}: %+v", got)
	}
}

func TestHarvestPrefersCollectionSharingTheOperationsWords(t *testing.T) {
	lists := []harvestList{{path: "/common/announcement-categories"}, {path: "/common/office-categories"}, {path: "/common/quick-link-categories"}}
	if got := candidateLists("/common/office-contacts/category/{categoryId}", "categoryId", lists); len(got) == 0 || got[0].path != "/common/office-categories" {
		t.Fatalf("office contacts took the wrong categories collection: %+v", got)
	}
	if got := candidateLists("/common/office-contacts/category/{categoryId}", "categoryId", lists); len(got) != 1 {
		t.Fatalf("an unrelated categories collection is still a fallback: %+v", got)
	}
	if got := candidateLists("/common/quick-links/category/{categoryId}", "categoryId", lists); len(got) == 0 || got[0].path != "/common/quick-link-categories" {
		t.Fatalf("quick links took the wrong categories collection: %+v", got)
	}
}

package stagedlab

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestVariantsAreDistinctAndCatalogLinksAllOfThem(t *testing.T) {
	variants := Variants()
	if len(variants) != VariantCount {
		t.Fatalf("variants = %d, want %d", len(variants), VariantCount)
	}
	seen := map[string]bool{}
	for _, v := range variants {
		if seen[v] {
			t.Fatalf("duplicate variant %q", v)
		}
		seen[v] = true
	}
	lab := Start(t)
	body := get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"catalog")
	for _, v := range variants {
		if !strings.Contains(body, `href="`+strings.ReplaceAll(v, "&", "&amp;")+`"`) {
			t.Fatalf("catalog does not link %q", v)
		}
	}
}

func TestIdentitiesHaveSeparateMarkersAndAnonymousIsRejected(t *testing.T) {
	lab := Start(t)
	for user, want := range map[string]struct{ password, marker string }{
		AdminUser:  {AdminPassword, AdminMarker},
		ViewerUser: {ViewerPassword, ViewerMarker},
	} {
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar}
		resp, err := client.PostForm(lab.Primary.URL+PathPrefix+"login", url.Values{"csrf": {CSRFValue}, "username": {user}, "password": {want.password}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), want.marker) {
			t.Fatalf("%s: status=%d body=%q", user, resp.StatusCode, body)
		}
	}
	if status := status(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"private"); status != http.StatusUnauthorized {
		t.Fatalf("anonymous private status = %d", status)
	}
	resp, _ := http.PostForm(lab.Primary.URL+PathPrefix+"login", url.Values{"username": {AdminUser}, "password": {AdminPassword}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login without CSRF accepted: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestGraphQLIntrospectionDiffersBetweenOrigins(t *testing.T) {
	lab := Start(t)
	query := `{"query":"{ __schema { queryType { name } } }"}`
	primary := post(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"graphql", query)
	if !strings.Contains(primary, `"__schema"`) || strings.Contains(primary, "errors") {
		t.Fatalf("primary introspection: %s", primary)
	}
	secondary := post(t, lab.Secondary.Client(), lab.Secondary.URL+"/graphql", query)
	if !strings.Contains(secondary, "introspection is disabled") {
		t.Fatalf("secondary introspection: %s", secondary)
	}
}

func TestOpenAPIValidAndLookalikes(t *testing.T) {
	lab := Start(t)
	var valid struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"openapi.json")), &valid); err != nil || len(valid.Paths) != 2 {
		t.Fatalf("valid document: %v %+v", err, valid)
	}
	var lookalike struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"openapi-lookalike.json")), &lookalike); err == nil {
		t.Fatal("lookalike must not decode as an OpenAPI path map")
	}
	if !strings.Contains(get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"api-docs"), "prose") {
		t.Fatal("html lookalike missing")
	}
}

func TestRecordsResourceCreateAndCleanup(t *testing.T) {
	lab := Start(t)
	created := post(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"api/records", "name=probe")
	var out struct{ ID string }
	if err := json.Unmarshal([]byte(created), &out); err != nil || out.ID == "" || lab.Resources() != 1 {
		t.Fatalf("create: %v %q resources=%d", err, created, lab.Resources())
	}
	req, _ := http.NewRequest(http.MethodDelete, lab.Primary.URL+PathPrefix+"api/records/"+out.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent || lab.Resources() != 0 {
		t.Fatalf("cleanup: %v %v resources=%d", err, resp, lab.Resources())
	}
}

func TestForbiddenTrafficIsRecorded(t *testing.T) {
	lab := Start(t)
	get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"about")
	get(t, http.DefaultClient, lab.Primary.URL+strings.TrimSuffix(PathPrefix, "/"))
	if len(lab.Forbidden()) != 0 {
		t.Fatalf("approved traffic flagged: %+v", lab.Forbidden())
	}
	get(t, http.DefaultClient, lab.Primary.URL+OutsidePath)
	get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"logout")
	post(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"write", "note=x")
	get(t, http.DefaultClient, lab.Alias.URL+"/anything")
	// A redirect off the approved origin is followed by this client and recorded.
	get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"redirect-out")
	if got := len(lab.Forbidden()); got != 5 {
		t.Fatalf("forbidden hits = %d: %+v", got, lab.Forbidden())
	}
	lab.Reset()
	if len(lab.Hits()) != 0 {
		t.Fatal("reset left hits")
	}
}

func TestDeadURLRefusesConnections(t *testing.T) {
	lab := Start(t)
	if _, err := http.Get(lab.DeadURL); err == nil {
		t.Fatal("dead origin accepted a connection")
	}
}

func get(t *testing.T, c *http.Client, target string) string {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func status(t *testing.T, c *http.Client, target string) int {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func post(t *testing.T, c *http.Client, target, body string) string {
	t.Helper()
	contentType := "application/x-www-form-urlencoded"
	if strings.HasPrefix(body, "{") {
		contentType = "application/json"
	}
	resp, err := c.Post(target, contentType, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

func TestControlHandlerReportsAndResets(t *testing.T) {
	lab := Start(t)
	control := httptestServer(t, lab.ControlHandler())
	get(t, http.DefaultClient, lab.Alias.URL+"/x")
	request := func(method, path string, header bool) *http.Response {
		req, _ := http.NewRequest(method, control+path, nil)
		if header {
			req.Header.Set("X-Lab-Control", "local-only")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := request(http.MethodGet, "/forbidden", false); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("control without header: %d", resp.StatusCode)
	}
	resp := request(http.MethodGet, "/forbidden", true)
	var hits []Hit
	if err := json.NewDecoder(resp.Body).Decode(&hits); err != nil || len(hits) != 1 || hits[0].Origin != "alias" {
		t.Fatalf("forbidden: %v %+v", err, hits)
	}
	if resp := request(http.MethodPost, "/reset", true); resp.StatusCode != http.StatusNoContent || len(lab.Hits()) != 0 {
		t.Fatalf("reset: %d hits=%d", resp.StatusCode, len(lab.Hits()))
	}
	if len(lab.Hits()) != 0 {
		t.Fatal("control calls must not be recorded")
	}
}

func httptestServer(t *testing.T, h http.Handler) string {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return server.URL
}

func TestGraphQLOverGETIntrospectionAndDisabledSibling(t *testing.T) {
	lab := Start(t)
	introspection := url.QueryEscape(`{ __schema { queryType { name fields { name } } } }`)
	body := get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"graphql?query="+introspection)
	var decoded struct {
		Data struct {
			Schema struct {
				QueryType struct {
					Fields []struct{ Name string }
				} `json:"queryType"`
				MutationType struct {
					Fields []struct{ Name string }
				} `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil || len(decoded.Data.Schema.QueryType.Fields) != 1 || decoded.Data.Schema.QueryType.Fields[0].Name != "record" || decoded.Data.Schema.MutationType.Fields[0].Name != "deleteRecord" {
		t.Fatalf("introspection shape: %v %s", err, body)
	}
	value := get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"graphql?query="+url.QueryEscape(`query($id: ID!){ record(id: $id) }`)+"&variables="+url.QueryEscape(`{"id":"rec-1"}`))
	if !strings.Contains(value, `"record":"rec-1"`) {
		t.Fatalf("variables were not applied: %s", value)
	}
	disabled := get(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"graphql-noint?query="+introspection)
	if !strings.Contains(disabled, "introspection is disabled") {
		t.Fatalf("sibling endpoint must answer 200 with introspection disabled: %s", disabled)
	}
}

func TestNotesAndRecordsHavePurgeAllCleanupRoutes(t *testing.T) {
	lab := Start(t)
	post(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"api/notes", "text=one")
	post(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"api/records", "name=a")
	post(t, http.DefaultClient, lab.Primary.URL+PathPrefix+"api/records", "name=b")
	if lab.Resources() != 3 {
		t.Fatalf("resources = %d", lab.Resources())
	}
	del := func(path string) int {
		req, _ := http.NewRequest(http.MethodDelete, lab.Primary.URL+PathPrefix+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if del("api/notes/fixture") != http.StatusNoContent || lab.Resources() != 2 {
		t.Fatalf("notes cleanup left %d resources", lab.Resources())
	}
	if del("api/records/fixture") != http.StatusNoContent || lab.Resources() != 0 {
		t.Fatalf("records cleanup left %d resources", lab.Resources())
	}
	if del("api/records/fixture") != http.StatusNoContent {
		t.Fatal("cleanup must be idempotent")
	}
}

func TestSpecDocumentsAreServedByTheControlAPI(t *testing.T) {
	lab := Start(t)
	control := httptestServer(t, lab.ControlHandler())
	fetch := func(name string) string {
		req, _ := http.NewRequest(http.MethodGet, control+"/specs/"+name, nil)
		req.Header.Set("X-Lab-Control", "local-only")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", name, err, resp)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return string(data)
	}
	var valid struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(fetch("openapi.json")), &valid); err != nil || valid.Paths["/admin"]["get"].OperationID != "getAdminPanel" || valid.Paths["/api/notes"]["post"].OperationID != "createNote" {
		t.Fatalf("openapi document: %v %+v", err, valid)
	}
	if !strings.Contains(fetch("schema.graphql"), "type Query") || !strings.Contains(fetch("introspection.json"), "__schema") {
		t.Fatal("graphql documents missing")
	}
	req, _ := http.NewRequest(http.MethodGet, control+"/specs/openapi.json", nil)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusNotFound {
		t.Fatal("spec endpoint must require the control header")
	}
}

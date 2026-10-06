package stagedlab

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
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

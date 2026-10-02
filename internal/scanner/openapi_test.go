package scanner

import "testing"

func TestParseOpenAPIJSONAndRejectRemoteRefs(t *testing.T) {
	got, err := ParseOpenAPI([]byte(`{"openapi":"3.0.0","paths":{"/users":{"get":{},"post":{}},"/health":{"parameters":[]}}}`), "https://example.test")
	if err != nil || len(got) != 2 || got[0].Origin != "https://example.test" {
		t.Fatalf("got %#v err %v", got, err)
	}
	if got[0].Method != "GET" || got[1].Method != "POST" || got[0].Path != "/users" {
		t.Fatalf("operation order must be stable by path and method: %+v", got)
	}
	if !got[0].Eligible || got[1].Eligible || got[1].Reason == "" {
		t.Fatalf("safe and mutating operations were not distinguished: %+v", got)
	}
	yaml := []byte("openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    X:\n      $ref:  https://evil.test/x\n")
	if _, err := ParseOpenAPI(yaml, "https://example.test"); err == nil {
		t.Fatal("remote ref accepted")
	}
}

func TestParseOpenAPIReportsUnresolvedParametersAndLocalReferenceErrors(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","paths":{"/users/{id}":{"get":{}},"/search":{"get":{"parameters":[{"name":"q","in":"query","required":true}]}}}}`)
	got, err := ParseOpenAPI(data, "https://example.test")
	if err != nil || len(got) != 2 {
		t.Fatalf("parse=%+v err=%v", got, err)
	}
	for _, endpoint := range got {
		if endpoint.Resolved || endpoint.Eligible || endpoint.Reason == "" {
			t.Errorf("unresolved operation was eligible: %+v", endpoint)
		}
	}
	broken := []byte(`{"openapi":"3.0.0","paths":{"/a":{"get":{}}},"components":{"schemas":{"A":{"$ref":"#/components/schemas/Missing"}}}}`)
	if _, err := ParseOpenAPI(broken, "https://example.test"); err == nil {
		t.Fatal("unresolvable local ref accepted")
	}
}

func TestAPIEndpointURLPreservesApplicationPathAndRejectsScopeEscape(t *testing.T) {
	target := "https://Example.test:8443/Portal/Case/"
	endpoint := APIEndpoint{Method: "GET", Path: "/users", Origin: "https://example.test:8443", Resolved: true, Eligible: true}
	got, err := apiEndpointURL(target, endpoint)
	if err != nil || got != "https://example.test:8443/Portal/Case/users" {
		t.Fatalf("URL=%q err=%v", got, err)
	}
	endpoint.Origin = "https://other.example.test"
	if _, err := apiEndpointURL(target, endpoint); err == nil {
		t.Fatal("foreign OpenAPI origin accepted")
	}
	endpoint.Origin = "https://example.test:8443"
	endpoint.Path = "/../outside"
	if _, err := apiEndpointURL(target, endpoint); err == nil {
		t.Fatal("path traversal accepted")
	}
	endpoint.Path = "/%2e%2e/outside"
	if _, err := apiEndpointURL(target, endpoint); err == nil {
		t.Fatal("encoded path traversal accepted")
	}
}

func TestParseOpenAPIValidatesDialectOriginAndBounds(t *testing.T) {
	swagger := []byte(`{"swagger":"2.0","paths":{"/v1":{"get":{}}}}`)
	if got, err := ParseOpenAPI(swagger, "https://example.test:8443"); err != nil || len(got) != 1 {
		t.Fatalf("Swagger 2.0 parse = %+v err=%v", got, err)
	}
	if _, err := ParseOpenAPI([]byte(`{"openapi":"3.2.0","paths":{}}`), "https://example.test"); err == nil {
		t.Fatal("unsupported OpenAPI version accepted")
	}
	if _, err := ParseOpenAPI([]byte(`{"openapi":"3.0.0","paths":{}}`), "https://user:pass@example.test"); err == nil {
		t.Fatal("origin containing credentials accepted")
	}
	if _, err := ParseOpenAPI(make([]byte, MaxOpenAPISpecBytes+1), "https://example.test"); err == nil {
		t.Fatal("oversized specification accepted")
	}
}

func TestParseOpenAPIRejectsNonLocalReferenceForms(t *testing.T) {
	for _, ref := range []string{"https://evil.test/schema.json", "../schema.json", "file:///etc/passwd"} {
		data := []byte(`{"openapi":"3.0.1","paths":{},"components":{"schemas":{"X":{"$ref":"` + ref + `"}}}}`)
		if _, err := ParseOpenAPI(data, "https://example.test"); err == nil {
			t.Errorf("external reference %q accepted", ref)
		}
	}
}

func TestParseOpenAPIHeadIsSafeReadOperation(t *testing.T) {
	endpoints, err := ParseOpenAPI([]byte(`{"openapi":"3.1.0","paths":{"/health":{"head":{},"post":{}}}}`), "https://example.test/app")
	if err != nil || len(endpoints) != 2 {
		t.Fatalf("endpoints=%+v err=%v", endpoints, err)
	}
	if endpoints[0].Method != "HEAD" || !endpoints[0].Eligible {
		t.Fatalf("HEAD was not eligible: %+v", endpoints[0])
	}
	if _, err := apiEndpointURL("https://example.test/app", endpoints[0]); err != nil {
		t.Fatalf("HEAD URL: %v", err)
	}
	if endpoints[1].Eligible {
		t.Fatalf("POST became eligible without approval: %+v", endpoints[1])
	}
}

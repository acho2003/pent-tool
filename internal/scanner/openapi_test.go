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
	yaml := []byte("openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    X:\n      $ref:  https://evil.test/x\n")
	if _, err := ParseOpenAPI(yaml, "https://example.test"); err == nil {
		t.Fatal("remote ref accepted")
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

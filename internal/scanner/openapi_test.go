package scanner

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

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

func TestParseOpenAPIResolvesLocalParameterReferences(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","components":{"parameters":{"Id":{"name":"id","in":"query","required":true,"schema":{"type":"string"}}}},"paths":{"/items":{"get":{"parameters":[{"$ref":"#/components/parameters/Id"}]}}}}`)
	got, err := ParseOpenAPI(data, "https://example.test")
	if err != nil || len(got) != 1 {
		t.Fatalf("operations=%+v err=%v", got, err)
	}
	if got[0].Resolved || got[0].Eligible {
		t.Fatalf("required referenced input was guessed: %+v", got[0])
	}
}

func TestParseOpenAPIRejectsCyclicPathReferences(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","paths":{"/items":{"$ref":"#/components/pathItems/A"}},"components":{"pathItems":{"A":{"$ref":"#/components/pathItems/A"}}}}`)
	if _, err := ParseOpenAPI(data, "https://example.test"); err == nil {
		t.Fatal("cyclic path reference accepted")
	}
}

func TestParseOpenAPIExposesRequiredInputsSecurityAndDeclaredServers(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","servers":[{"url":"https://api.example.test/v2"}],"security":[{"bearerAuth":[]}],"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}},"parameters":{"Filter":{"name":"filter","in":"query","required":true,"schema":{"type":"string"}}},"requestBodies":{"CreateItem":{"required":true,"content":{"application/json":{"schema":{"type":"object"}},"application/xml":{"schema":{"type":"object"}}}}}},"paths":{"/items":{"get":{"parameters":[{"$ref":"#/components/parameters/Filter"}]},"post":{"requestBody":{"$ref":"#/components/requestBodies/CreateItem"},"security":[]}}}}`)
	endpoints, err := ParseOpenAPI(data, "https://approved.example.test/app")
	if err != nil || len(endpoints) != 2 {
		t.Fatalf("endpoints=%+v err=%v", endpoints, err)
	}
	get := endpoints[0]
	if get.Method != "GET" || get.Resolved || len(get.Parameters) != 1 || get.Parameters[0] != (APIParameter{Name: "filter", Location: "query", Required: true, SchemaType: "string"}) {
		t.Fatalf("required query metadata=%+v", get)
	}
	if len(get.SecuritySchemes) != 1 || get.SecuritySchemes[0] != "bearerAuth" || len(get.SpecServers) != 1 || get.SpecServers[0] != "https://api.example.test/v2" || get.Origin != "https://approved.example.test/app" {
		t.Fatalf("server/security mapping metadata=%+v", get)
	}
	post := endpoints[1]
	if post.Method != "POST" || post.Eligible || !post.RequestBodyRequired || len(post.RequestBodyContentTypes) != 2 || len(post.SecuritySchemes) != 0 {
		t.Fatalf("write request metadata=%+v", post)
	}
}

func TestMaterializeOpenAPIOperationUsesDeclaredValuesAndKeepsTemplate(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","paths":{"/items/{itemId}":{"get":{"operationId":"getItem","parameters":[{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}},{"name":"filter","in":"query","required":true,"schema":{"type":"string"}},{"name":"page","in":"query","required":false,"schema":{"type":"integer"}}]}}}}`)
	endpoints, err := ParseOpenAPI(data, "https://api.example.test/v1")
	if err != nil || len(endpoints) != 1 {
		t.Fatalf("parse=%+v err=%v", endpoints, err)
	}
	definitionID := "abc"
	input := assessment.APIOperationInput{DefinitionID: definitionID, OperationID: "getItem", PathParams: map[string]string{"itemId": "42"}, Query: map[string]string{"filter": "new item", "page": "2"}}
	materialized := MaterializeOpenAPIOperations(endpoints, definitionID, "https://api.example.test/v1", []assessment.APIOperationInput{input})
	got := materialized[0]
	if !got.Resolved || !got.Eligible || got.Path != "/items/{itemId}" || got.OperationID != "getItem" || got.RequestURL != "https://api.example.test/v1/items/42?filter=new+item&page=2" {
		t.Fatalf("operation was not materialized safely: %+v", got)
	}
	if len(got.MissingInputs) != 0 {
		t.Fatalf("unexpected missing inputs: %v", got.MissingInputs)
	}
}

func TestMaterializeOpenAPIRequiresAllInputsAndRejectsUndeclaredValues(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","paths":{"/items/{itemId}":{"get":{"operationId":"getItem","parameters":[{"name":"itemId","in":"path","required":true},{"name":"filter","in":"query","required":true}]}}}}`)
	endpoints, err := ParseOpenAPI(data, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	definitionID := "abc"
	missing := MaterializeOpenAPIOperations(endpoints, definitionID, "https://api.example.test", nil)[0]
	if missing.Resolved || missing.Eligible || len(missing.MissingInputs) != 2 || missing.RequestURL != "" {
		t.Fatalf("missing inputs were guessed: %+v", missing)
	}
	bad := assessment.APIOperationInput{DefinitionID: definitionID, OperationID: "getItem", PathParams: map[string]string{"itemId": "../escape"}, Query: map[string]string{"filter": "all", "admin": "true"}}
	rejected := MaterializeOpenAPIOperations(endpoints, definitionID, "https://api.example.test", []assessment.APIOperationInput{bad})[0]
	if rejected.Resolved || rejected.Eligible || len(rejected.MissingInputs) != 2 {
		t.Fatalf("unsafe/undeclared inputs accepted: %+v", rejected)
	}
}

func TestMaterializeOpenAPIDoesNotTreatRequiredHeadersAsSatisfied(t *testing.T) {
	data := []byte(`{"openapi":"3.1.0","paths":{"/items":{"get":{"operationId":"listItems","parameters":[{"name":"X-Tenant","in":"header","required":true}]}}}}`)
	endpoints, err := ParseOpenAPI(data, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	got := MaterializeOpenAPIOperations(endpoints, "spec", "https://api.example.test", nil)[0]
	if got.Resolved || got.Eligible || len(got.MissingInputs) != 1 || got.MissingInputs[0] != "header:X-Tenant" {
		t.Fatalf("required header was silently omitted: %+v", got)
	}
}

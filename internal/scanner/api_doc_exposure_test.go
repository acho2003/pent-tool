package scanner

import (
	"net/http"
	"testing"
)

func respWith(status int, ct string) *http.Response {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{StatusCode: status, Header: h}
}

func TestClassifyAPIDocExposure(t *testing.T) {
	cases := []struct {
		name   string
		status int
		ct     string
		body   string
		want   string // "" = not a finding, else expected severity
	}{
		{"swagger-ui html", 200, "text/html", `<html><body><div id="swagger-ui"></div><script>window.onload=function(){SwaggerUIBundle({url:"/openapi.json"})}</script></body></html>`, "medium"},
		{"redoc html", 200, "text/html", `<html><body><redoc spec-url="/openapi.json"></redoc><script>Redoc.init("/openapi.json")</script></body></html>`, "medium"},
		{"graphiql html", 200, "text/html", `<html><title>GraphiQL</title><body>graphiql</body></html>`, "medium"},
		{"openapi json spec", 200, "application/json", `{"openapi":"3.0.0","info":{},"paths":{"/x":{}}}`, "low"},
		{"swagger json spec", 200, "application/json", `{"swagger":"2.0","paths":{"/x":{}}}`, "low"},
		{"graphql introspection", 200, "application/json", `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`, "medium"},
		{"generic SPA html", 200, "text/html", `<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`, ""},
		{"plain json not a spec", 200, "application/json", `{"status":"ok","data":[]}`, ""},
		{"404", 404, "text/html", `not found`, ""},
		{"empty 200", 200, "application/json", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classifyAPIDocExposure(exposureCheck{}, respWith(tc.status, tc.ct), []byte(tc.body))
			if tc.want == "" {
				if v.Classification != "" {
					t.Fatalf("expected no finding, got %+v", v)
				}
				return
			}
			if v.Classification != "api_documentation_exposed" {
				t.Fatalf("expected a finding, got %+v", v)
			}
			if v.Severity != tc.want {
				t.Fatalf("severity = %q, want %q", v.Severity, tc.want)
			}
			if v.Title == "" {
				t.Fatalf("finding must carry a title")
			}
		})
	}
}

func TestAPIDocsRunnerRegistered(t *testing.T) {
	if !HasAssessmentRunner("api-docs") {
		t.Fatalf("api-docs must be a registered assessment runner")
	}
}

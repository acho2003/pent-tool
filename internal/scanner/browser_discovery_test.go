package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"testing"
)

func TestBrowserRequestBoundary(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", Port: 443, PathPrefix: "/"}}, assessment.Exclusion{Method: "GET", PathPattern: "/logout", Reason: "ends session"})
	req := Request{AppScope: &scope}
	for _, tc := range []struct {
		method, url string
		allowed     bool
	}{{"GET", "https://app.test/api", true}, {"GET", "https://alias.test/api", false}, {"POST", "https://app.test/form", false}, {"GET", "https://app.test/logout", false}, {"GET", "http://app.test/", false}} {
		if err := browserRequestAllowed(req, Config{}, tc.method, tc.url); (err == nil) != tc.allowed {
			t.Fatalf("%s %s: %v", tc.method, tc.url, err)
		}
	}
}

func TestBrowserReadOnlyGraphQLPOSTPolicy(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", Port: 443, PathPrefix: "/"}}, assessment.Exclusion{Method: "POST", PathPattern: "/excluded"})
	req := Request{AppScope: &scope}
	for _, tc := range []struct {
		name, url, body string
		allowed         bool
	}{
		{"read", "https://app.test/graphql", `{"query":"query {viewer}"}`, true},
		{"variables", "https://app.test/graphql", `{"query":"query Read($id: ID!) {user(id:$id){name}}","operationName":"Read","variables":{"id":"explicit"}}`, true},
		{"mutation", "https://app.test/graphql", `{"query":"mutation {deleteUser}"}`, false},
		{"mixed", "https://app.test/graphql", `{"query":"query Read {viewer} mutation Write {deleteUser}","operationName":"Read"}`, false},
		{"subscription", "https://app.test/graphql", `{"query":"subscription {events}"}`, false},
		{"opaque", "https://app.test/graphql", `{"extensions":{"persistedQuery":{"sha256Hash":"opaque"}}}`, false},
		{"batch", "https://app.test/graphql", `[{"query":"{viewer}"}]`, false},
		{"ambiguous", "https://app.test/graphql", `{"query":"query A {viewer} query B {viewer}"}`, false},
		{"missing selection", "https://app.test/graphql", `{"query":"query A {viewer}","operationName":"B"}`, false},
		{"alias", "https://alias.test/graphql", `{"query":"{viewer}"}`, false},
		{"excluded", "https://app.test/excluded", `{"query":"{viewer}"}`, false},
		{"URL mutation", "https://app.test/graphql?query=mutation%20%7BdeleteUser%7D", `{"query":"{viewer}"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := browserDiscoveryRequestAllowed(req, Config{}, "POST", tc.url, "application/json", []byte(tc.body))
			if (err == nil) != tc.allowed {
				t.Fatal(err)
			}
		})
	}
	if browserRequestAllowed(req, Config{}, "POST", "https://app.test/graphql") == nil {
		t.Fatal("active adapter policy silently expanded")
	}
}

func TestBrowserBodyMetadataKeepsVariantsWithoutPersistingSecrets(t *testing.T) {
	artifact := writeKatanaFixture(t, `{"request":{"endpoint":"https://app.test/graphql","method":"POST","body_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headers":{"content-type":"application/json"},"parameters":[{"name":"variables.id","location":"body"}]},"response":{"status_code":200}}
{"request":{"endpoint":"https://app.test/graphql","method":"POST","body_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","headers":{"content-type":"application/json"},"parameters":[{"name":"variables.id","location":"body"}]},"response":{"status_code":200}}`)
	surface, err := ParseKatanaAttackSurface(artifact, "app:test", "https://app.test/", false)
	if err != nil || len(surface.Endpoints) != 2 {
		t.Fatalf("body variants lost: %+v %v", surface, err)
	}
	for _, endpoint := range surface.Endpoints {
		if endpoint.BodyDigest == "" || len(endpoint.Parameters) != 1 || endpoint.Parameters[0].Name != "variables.id" {
			t.Fatalf("body metadata lost: %+v", endpoint)
		}
	}
}

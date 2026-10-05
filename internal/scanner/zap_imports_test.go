package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net/url"
	"strings"
	"testing"
)

func TestZAPRequiresPinnedAddonInventory(t *testing.T) {
	call := func(_ string, _ url.Values) (map[string]any, error) {
		return map[string]any{"installedAddons": []any{map[string]any{"id": "network", "version": "0.28.0"}, map[string]any{"id": "openapi", "version": "56.0.0"}, map[string]any{"id": "graphql", "version": "0.33.0"}}}, nil
	}
	if err := verifyZAPAddons(call); err != nil {
		t.Fatal(err)
	}
	if err := verifyZAPAddons(func(_ string, _ url.Values) (map[string]any, error) { return map[string]any{}, nil }); err == nil {
		t.Fatal("missing addons accepted")
	}
}
func TestFilteredGraphQLRemovesUnresolvedQueriesAndMutations(t *testing.T) {
	operations, err := ParseAPIDefinition([]byte(`type Query { ping: String hidden(id: ID!): String } type Mutation { erase: Boolean }`), "https://app.test/graphql")
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := assessment.ParseApprovedOrigin("app", "https://app.test/")
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	data, destination, err := zapFilteredGraphQL(operations, &scope)
	if err != nil {
		t.Fatal(err)
	}
	if destination != "https://app.test/graphql" || !strings.Contains(string(data), "ping") || strings.Contains(string(data), "hidden") || strings.Contains(string(data), "Mutation") || strings.Contains(string(data), "erase") {
		t.Fatalf("unfiltered definition %s at %s", data, destination)
	}
	if err := browserRequestAllowed(Request{AppScope: &scope}, Config{}, "GET", "https://app.test/graphql?query=mutation%20%7B%20erase%20%7D"); err == nil {
		t.Fatal("GET mutation accepted")
	}
}

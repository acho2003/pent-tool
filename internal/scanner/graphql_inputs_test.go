package scanner

import (
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net/url"
	"strings"
	"testing"
)

func TestGraphQLMaterializesOnlySuppliedTypedQueryInputs(t *testing.T) {
	schema := []byte(`enum State { ACTIVE CLOSED } input Filter { state: State! limit: Int } type User { id: ID! } type Query { user(id: ID!, filter: Filter): User } type Mutation { erase(id: ID!): Boolean }`)
	endpoints, err := ParseAPIDefinition(schema, "https://app.test/")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []assessment.APIOperationInput{{DefinitionID: "schema", OperationID: "query user", Query: map[string]string{"id": "supplied-42", "filter": `{"state":"ACTIVE","limit":2}`}}}
	got := MaterializeGraphQLOperations(schema, endpoints, "schema", inputs)
	for _, op := range got {
		if op.Method == "POST" {
			if op.Eligible {
				t.Fatal("mutation made eligible")
			}
			continue
		}
		if !op.Eligible || !op.Resolved || len(op.MissingInputs) > 0 {
			t.Fatalf("query unresolved: %+v", op)
		}
		u, _ := url.Parse(op.RequestURL)
		if u.Path != "/graphql" || !strings.Contains(u.Query().Get("variables"), "supplied-42") || !strings.Contains(u.Query().Get("query"), "$id: ID!") {
			t.Fatal(op)
		}
	}
	for _, bad := range []map[string]string{{"id": "42", "filter": `{"state":"UNKNOWN"}`}, {"id": "42", "filter": `{"limit":2}`}, {"undeclared": "42"}} {
		got = MaterializeGraphQLOperations(schema, endpoints, "schema", []assessment.APIOperationInput{{DefinitionID: "schema", OperationID: "query user", Query: bad}})
		if got[0].Eligible {
			t.Fatal("invalid arguments were materialized", bad)
		}
	}
	missing := MaterializeGraphQLOperations(schema, endpoints, "schema", nil)
	if missing[0].Eligible || len(missing[0].MissingInputs) != 1 {
		t.Fatal(missing)
	}
}

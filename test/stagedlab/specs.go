package stagedlab

import (
	"encoding/json"
)

// Spec returns a definition document the lab owns, with paths relative to the
// approved target path (the assessment joins them to the target URL):
//
//	openapi.json            a valid OpenAPI 3.0 document
//	openapi-lookalike.json  has the openapi keys but is not a valid document
//	openapi-html.html       prose that mentions openapi
//	schema.graphql          a valid GraphQL SDL
//	introspection.json      an introspection result, which is not an SDL definition
func Spec(name string) (body, contentType string, ok bool) {
	switch name {
	case "openapi.json":
		return openAPIDocument(), "application/json", true
	case "openapi-lookalike.json":
		return `{"openapi":"3.0.3","info":"not an object","paths":["not","a","map"]}`, "application/json", true
	case "openapi-html.html":
		return `<html><body>"openapi": "3.0.0" appears in prose, not as a schema</body></html>`, "text/html", true
	case "schema.graphql":
		return "type Query {\n  record(id: ID!): String\n}\n\ntype Mutation {\n  deleteRecord(id: ID!): Boolean\n}\n", "text/plain", true
	case "introspection.json":
		return `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`, "application/json", true
	}
	return "", "", false
}

func openAPIDocument() string {
	response := map[string]any{"200": map[string]string{"description": "ok"}}
	form := map[string]any{"content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{"type": "object"}}}}
	pathID := []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}}
	doc := map[string]any{
		"openapi": "3.0.3", "info": map[string]string{"title": "Staged lab API", "version": "1"},
		"paths": map[string]any{
			"/api/records": map[string]any{
				"get":  map[string]any{"operationId": "listRecords", "responses": response},
				"post": map[string]any{"operationId": "createRecord", "requestBody": form, "responses": map[string]any{"201": map[string]string{"description": "created"}}},
			},
			"/api/records/{id}": map[string]any{
				"get": map[string]any{"operationId": "getRecord", "parameters": pathID, "responses": response},
			},
			"/api/notes": map[string]any{
				"post": map[string]any{"operationId": "createNote", "requestBody": form, "responses": map[string]any{"201": map[string]string{"description": "created"}}},
			},
			"/admin": map[string]any{
				"get": map[string]any{"operationId": "getAdminPanel", "responses": response},
			},
		},
	}
	out, _ := json.Marshal(doc)
	return string(out)
}

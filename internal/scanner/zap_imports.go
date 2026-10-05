package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

var testedZAPAddons = map[string]string{"network": "0.28.0", "openapi": "56.0.0", "graphql": "0.33.0"}

func verifyZAPAddons(call zapCallFunc) error {
	result, err := call("/JSON/autoupdate/view/installedAddons/", url.Values{})
	if err != nil {
		return fmt.Errorf("required ZAP add-on inventory unavailable")
	}
	installed := map[string]string{}
	if addons, ok := result["installedAddons"].([]any); ok {
		for _, raw := range addons {
			if addon, ok := raw.(map[string]any); ok {
				installed[valueString(addon, "id")] = valueString(addon, "version")
			}
		}
	}
	for _, name := range []string{"network", "openapi", "graphql"} {
		if installed[name] != testedZAPAddons[name] {
			return fmt.Errorf("ZAP %s add-on requires tested version %s; installed %s", name, testedZAPAddons[name], installed[name])
		}
	}
	return nil
}

type DefinitionImport struct {
	DefinitionID string `json:"definition_id"`
	Kind         string `json:"kind"`
	Origin       string `json:"origin"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	EvidenceRef  string `json:"evidence_reference,omitempty"`
}

// Native imports complement exact method-aware seeds. No unresolved parameter
// defaults or external servers are handed to a schema-generated request sender.
func zapImportDefinitions(ctx context.Context, cfg Config, req Request, contextID string) []DefinitionImport {
	var results []DefinitionImport
	origins := map[string]map[string]any{}
	graphs := map[string][]APIEndpoint{}
	for _, endpoint := range req.APIEndpoints {
		raw := endpoint.RequestURL
		if raw == "" {
			raw, _ = apiEndpointURL(req.Target, endpoint)
		}
		if endpoint.Source == "graphql" && endpoint.DefinitionSDL != "" {
			graphs[endpoint.DefinitionID] = append(graphs[endpoint.DefinitionID], endpoint)
			continue
		}
		if !endpoint.Eligible || !endpoint.Resolved || (endpoint.Method != "GET" && endpoint.Method != "HEAD") {
			continue
		}
		if req.AppScope == nil {
			continue
		}
		if ok, _ := req.AppScope.Allows(raw); !ok {
			continue
		}
		if excluded, _ := req.AppScope.Excluded(endpoint.Method, raw); excluded {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.RawQuery != "" || len(endpoint.Parameters) > 0 || endpoint.RequestBodyRequired {
			continue
		}
		origin, _ := assessment.ParseApprovedOrigin("", raw)
		key := origin.Origin()
		if origins[key] == nil {
			origins[key] = map[string]any{}
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		entry, ok := origins[key][path].(map[string]any)
		if !ok {
			entry = map[string]any{}
			origins[key][path] = entry
		}
		entry[strings.ToLower(endpoint.Method)] = map[string]any{"responses": map[string]any{"200": map[string]string{"description": "Approved operation"}}}
	}
	keys := make([]string, 0, len(origins))
	for key := range origins {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, origin := range keys {
		data, _ := json.Marshal(map[string]any{"openapi": "3.0.3", "info": map[string]string{"title": "Approved Xalgorix API operations", "version": "1"}, "servers": []map[string]string{{"url": origin}}, "paths": origins[origin]})
		id := inventoryID(string(data))
		result := DefinitionImport{DefinitionID: id, Kind: "openapi", Origin: origin, Status: "imported", EvidenceRef: "${XFER}/xalgorix/" + id + ".json"}
		if err := zapUploadDefinition(ctx, cfg, "xalgorix/"+id+".json", data); err != nil {
			result.Status, result.Reason = "failed", "ZAP definition transfer unavailable"
		} else if err := zapPost(cfg, "/JSON/openapi/action/importFile/", url.Values{"file": {result.EvidenceRef}, "target": {origin}, "contextId": {contextID}, "maxMessages": {"1000"}}); err != nil {
			result.Status, result.Reason = "failed", "ZAP OpenAPI import rejected"
		}
		results = append(results, result)
	}
	keys = nil
	for key := range graphs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, id := range keys {
		operations := graphs[id]
		data, destination, err := zapFilteredGraphQL(operations, req.AppScope)
		if err != nil {
			results = append(results, DefinitionImport{DefinitionID: id, Kind: "graphql", Status: "skipped", Reason: err.Error()})
			continue
		}
		result := DefinitionImport{DefinitionID: id, Kind: "graphql", Origin: SafeTelemetryURL(destination), Status: "imported", EvidenceRef: "${XFER}/xalgorix/" + inventoryID(id, req.AttemptID) + ".graphql"}
		// Turn off generated queries: exact materialized read queries are seeded
		// separately, and schema defaults never invent business inputs.
		state, err := zapPostResponse(ctx, cfg, "/JSON/graphql/view/optionQueryGenEnabled/", url.Values{})
		prior := valueString(state, "QueryGenEnabled")
		if prior == "<nil>" {
			prior = valueString(state, "optionQueryGenEnabled")
		}
		if err != nil || (prior != "true" && prior != "false") {
			result.Status, result.Reason = "failed", "GraphQL query generation state unavailable"
			results = append(results, result)
			continue
		}
		if err = zapPost(cfg, "/JSON/graphql/action/setOptionQueryGenEnabled/", url.Values{"Boolean": {"false"}}); err == nil {
			err = zapUploadDefinition(ctx, cfg, strings.TrimPrefix(result.EvidenceRef, "${XFER}/"), data)
			if err == nil {
				err = zapPost(cfg, "/JSON/graphql/action/importFile/", url.Values{"file": {result.EvidenceRef}, "endurl": {destination}, "maxMessages": {"1000"}})
			}
		}
		if restoreErr := zapPost(cfg, "/JSON/graphql/action/setOptionQueryGenEnabled/", url.Values{"Boolean": {prior}}); restoreErr != nil {
			quarantineZAPService(cfg.ZAPURL, "restore GraphQL query generation failed")
			err = restoreErr
		}
		if err != nil {
			result.Status, result.Reason = "failed", "ZAP GraphQL import or cleanup failed"
		}
		results = append(results, result)
	}
	return results
}
func zapUploadDefinition(ctx context.Context, cfg Config, name string, data []byte) error {
	_, err := zapPostResponse(ctx, cfg, "/OTHER/core/other/fileUpload/", url.Values{"fileName": {name}, "fileContents": {string(data)}})
	return err
}
func zapFilteredGraphQL(operations []APIEndpoint, scope *assessment.AppScope) ([]byte, string, error) {
	if len(operations) == 0 || scope == nil {
		return nil, "", fmt.Errorf("approved GraphQL operations unavailable")
	}
	document, err := parser.ParseSchema(&ast.Source{Input: operations[0].DefinitionSDL})
	if err != nil {
		return nil, "", err
	}
	names := map[string]bool{}
	destination := ""
	for _, op := range operations {
		if !op.Eligible || !op.Resolved || !strings.HasPrefix(op.OperationID, "query ") {
			continue
		}
		u, err := url.Parse(op.RequestURL)
		if err != nil {
			continue
		}
		u.RawQuery = ""
		raw := u.String()
		if ok, _ := scope.Allows(raw); !ok {
			continue
		}
		if excluded, _ := scope.Excluded("GET", raw); excluded {
			continue
		}
		if destination != "" && destination != raw {
			return nil, "", fmt.Errorf("GraphQL definition has different destinations")
		}
		destination = raw
		names[strings.TrimPrefix(op.OperationID, "query ")] = true
	}
	if len(names) == 0 {
		return nil, "", fmt.Errorf("no approved materialized GraphQL queries")
	}
	queryName, mutationName, subscriptionName := "Query", "Mutation", "Subscription"
	for _, def := range document.Schema {
		for _, op := range def.OperationTypes {
			switch op.Operation {
			case ast.Query:
				queryName = op.Type
			case ast.Mutation:
				mutationName = op.Type
			case ast.Subscription:
				subscriptionName = op.Type
			}
		}
		var keep ast.OperationTypeDefinitionList
		for _, op := range def.OperationTypes {
			if op.Operation == ast.Query {
				keep = append(keep, op)
			}
		}
		def.OperationTypes = keep
	}
	var defs ast.DefinitionList
	for _, def := range document.Definitions {
		if def.Name == mutationName || def.Name == subscriptionName {
			continue
		}
		if def.Name == queryName {
			var fields ast.FieldList
			for _, field := range def.Fields {
				if names[field.Name] {
					fields = append(fields, field)
				}
			}
			def.Fields = fields
		}
		defs = append(defs, def)
	}
	document.Definitions = defs
	// Schema extensions can reintroduce roots or fields; refuse instead of widening.
	if len(document.Extensions) > 0 || len(document.SchemaExtension) > 0 {
		return nil, "", fmt.Errorf("GraphQL schema extensions require explicit filtered import support")
	}
	var out strings.Builder
	formatter.NewFormatter(&out).FormatSchemaDocument(document)
	return []byte(out.String()), destination, nil
}

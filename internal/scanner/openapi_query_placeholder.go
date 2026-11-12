package scanner

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Optional query parameters a definition declares for a read-only operation
// (pagination, sort order, search and filter fields) are the inputs injection
// checks need. Without values for them an operation is seeded as a bare path
// and parameter-based scanners have nothing to test.
//
// Placeholder values come from the definition itself (parameter example,
// schema example, default, first enum value) or, failing that, a fixed
// type-based token. They are never treated as operator-supplied inputs:
// supplied values always win, required inputs still have to be supplied, only
// GET/HEAD operations receive them, and every filled parameter is labelled in
// the endpoint's provenance.

const (
	queryPlaceholderUUID     = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	maxQueryPlaceholderBytes = 256
	placeholderProvenance    = "openapi-placeholder"
)

// openAPIQueryPlaceholder returns the placeholder for one query parameter, or
// "" when the definition gives no usable scalar (objects, deep structures).
func openAPIQueryPlaceholder(parameter, schema, root map[string]any) string {
	if value, ok := placeholderScalar(parameter["example"]); ok {
		return value
	}
	if examples, ok := parameter["examples"].(map[string]any); ok {
		names := make([]string, 0, len(examples))
		for name := range examples {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if example, err := resolveOpenAPIObject(root, examples[name]); err == nil {
				if value, ok := placeholderScalar(example["value"]); ok {
					return value
				}
			}
		}
	}
	if schema == nil {
		// Swagger 2.0 describes the type, enum and default on the parameter.
		schema = parameter
	}
	return schemaPlaceholder(schema, root, 0)
}

func schemaPlaceholder(schema, root map[string]any, depth int) string {
	if schema == nil || depth > 4 {
		return ""
	}
	for _, key := range []string{"example", "default"} {
		if value, ok := placeholderScalar(schema[key]); ok {
			return value
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		for _, candidate := range enum {
			if value, ok := placeholderScalar(candidate); ok {
				return value
			}
		}
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		list, _ := schema[key].([]any)
		for _, raw := range list {
			if sub, err := resolveOpenAPIObject(root, raw); err == nil {
				if value := schemaPlaceholder(sub, root, depth+1); value != "" {
					return value
				}
			}
		}
	}
	schemaType, _ := schema["type"].(string)
	if types, ok := schema["type"].([]any); ok { // OpenAPI 3.1 type arrays
		for _, raw := range types {
			if name, ok := raw.(string); ok && name != "null" {
				schemaType = name
				break
			}
		}
	}
	switch schemaType {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "array":
		if items, err := resolveOpenAPIObject(root, schema["items"]); err == nil {
			return schemaPlaceholder(items, root, depth+1)
		}
		return ""
	case "object":
		return ""
	case "string", "":
		if _, hasProperties := schema["properties"]; hasProperties && schemaType == "" {
			return ""
		}
		format, _ := schema["format"].(string)
		switch format {
		case "uuid":
			return queryPlaceholderUUID
		case "date":
			return "2024-01-01"
		case "date-time":
			return "2024-01-01T00:00:00Z"
		case "email":
			return "user@example.com"
		}
		return "test"
	}
	return ""
}

func placeholderScalar(value any) (string, bool) {
	var out string
	switch v := value.(type) {
	case string:
		out = v
	case float64:
		out = strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		out = strconv.Itoa(v)
	case int64:
		out = strconv.FormatInt(v, 10)
	case bool:
		out = strconv.FormatBool(v)
	case []any:
		if len(v) > 0 {
			return placeholderScalar(v[0])
		}
		return "", false
	default:
		return "", false
	}
	if out == "" || len(out) > maxQueryPlaceholderBytes || strings.ContainsAny(out, "\r\n\x00") {
		return "", false
	}
	return out, true
}

// withQueryPlaceholders appends placeholders for declared query parameters the
// URL does not already carry. Existing query text is kept byte for byte so
// supplied values and their encoding are preserved; it returns the names it
// filled, sorted. Only read-only OpenAPI operations are changed.
func withQueryPlaceholders(raw string, endpoint APIEndpoint) (string, []string) {
	if endpoint.Source != "openapi" || (endpoint.Method != "GET" && endpoint.Method != "HEAD") {
		return raw, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw, nil
	}
	present := parsed.Query()
	added := url.Values{}
	for _, parameter := range endpoint.Parameters {
		if parameter.Location != "query" || parameter.Placeholder == "" || present.Has(parameter.Name) || added.Has(parameter.Name) {
			continue
		}
		added.Set(parameter.Name, parameter.Placeholder)
	}
	if len(added) == 0 {
		return raw, nil
	}
	filled := make([]string, 0, len(added))
	for name := range added {
		filled = append(filled, name)
	}
	sort.Strings(filled)
	if parsed.RawQuery == "" {
		parsed.RawQuery = added.Encode()
	} else {
		parsed.RawQuery = parsed.RawQuery + "&" + added.Encode()
	}
	parsed.ForceQuery = false
	return parsed.String(), filled
}

// operationRequestURL is the concrete request an operation is seeded and
// matched with: its materialized URL (or the plain operation URL) plus query
// placeholders. Inventory, seeding and result bookkeeping all use it so the
// same operation always resolves to the same request.
func operationRequestURL(applicationURL string, endpoint APIEndpoint) (string, []string, error) {
	raw := endpoint.RequestURL
	if raw == "" {
		resolved, err := apiEndpointURL(applicationURL, endpoint)
		if err != nil {
			return "", nil, err
		}
		raw = resolved
	}
	withQuery, filled := withQueryPlaceholders(raw, endpoint)
	return withQuery, filled, nil
}

// optionalQueryParameters keeps the optional query parameter metadata of an
// operation whose path has been materialized, so later seeding can still add
// query placeholders.
func optionalQueryParameters(parameters []APIParameter) []APIParameter {
	var out []APIParameter
	for _, parameter := range parameters {
		if parameter.Location == "query" && !parameter.Required {
			out = append(out, parameter)
		}
	}
	return out
}

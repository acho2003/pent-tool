package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"gopkg.in/yaml.v3"
)

const MaxOpenAPISpecBytes = 5 << 20

type APIEndpoint struct {
	DefinitionSDL string `json:"-"`
	// RequestURL is a runtime-only concrete candidate from the already scoped
	// inventory. OpenAPI plans use Path/Origin and do not serialize sample URLs.
	RequestURL              string         `json:"-"`
	Method                  string         `json:"method"`
	Path                    string         `json:"path"`
	Origin                  string         `json:"origin,omitempty"`
	TargetID                string         `json:"target_id,omitempty"`
	DefinitionID            string         `json:"definition_id,omitempty"`
	OperationID             string         `json:"operation_id,omitempty"`
	MissingInputs           []string       `json:"missing_inputs,omitempty"`
	Source                  string         `json:"source"`
	Resolved                bool           `json:"resolved"`
	Eligible                bool           `json:"eligible"`
	Reason                  string         `json:"reason,omitempty"`
	Parameters              []APIParameter `json:"parameters,omitempty"`
	RequestBodyRequired     bool           `json:"request_body_required,omitempty"`
	RequestBodyContentTypes []string       `json:"request_body_content_types,omitempty"`
	SecuritySchemes         []string       `json:"security_schemes,omitempty"`
	SpecServers             []string       `json:"spec_servers,omitempty"`
}

type APIParameter struct {
	Name       string `json:"name"`
	Location   string `json:"location"`
	Required   bool   `json:"required,omitempty"`
	SchemaType string `json:"schema_type,omitempty"`
}

type APIEndpointResult struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Origin string `json:"origin,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func apiEndpointURL(applicationURL string, endpoint APIEndpoint) (string, error) {
	if endpoint.Source == "graphql" && endpoint.RequestURL == "" {
		return "", fmt.Errorf("materialized GraphQL query is unavailable; reload its definition and explicit inputs")
	}
	if endpoint.RequestURL == "" {
		for _, parameter := range endpoint.Parameters {
			if parameter.Required {
				return "", fmt.Errorf("materialized required operation inputs are unavailable")
			}
		}
	}
	if !endpoint.Eligible || !endpoint.Resolved || (endpoint.Method != "GET" && endpoint.Method != "HEAD") {
		return "", fmt.Errorf("operation is not eligible for the safe profile")
	}
	operationPath, err := url.PathUnescape(endpoint.Path)
	if err != nil || strings.ContainsAny(operationPath, "?#{}\\") {
		return "", fmt.Errorf("operation path is unresolved or contains URL delimiters")
	}
	for _, segment := range strings.Split(operationPath, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("operation path escapes application boundary")
		}
	}
	base, err := url.Parse(applicationURL)
	if err != nil || base.Host == "" || base.User != nil {
		return "", fmt.Errorf("invalid application URL")
	}
	base.Scheme = strings.ToLower(base.Scheme)
	base.Host = strings.ToLower(base.Host)
	if (base.Scheme == "https" && base.Port() == "443") || (base.Scheme == "http" && base.Port() == "80") {
		host := base.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		base.Host = host
	}
	if endpoint.Origin != "" {
		origin, parseErr := url.Parse(endpoint.Origin)
		if parseErr != nil || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || !strings.EqualFold(origin.Scheme, base.Scheme) || !strings.EqualFold(origin.Host, base.Host) {
			return "", fmt.Errorf("definition origin does not match mapped target")
		}
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + strings.TrimLeft(operationPath, "/")
	base.RawPath = ""
	base.RawQuery, base.Fragment = "", ""
	resolved := base.String()
	pattern, err := applicationContextRegex(applicationURL)
	if err != nil {
		return "", err
	}
	matched, err := regexp.MatchString(pattern, resolved)
	if err != nil || !matched {
		return "", fmt.Errorf("operation path is outside application context")
	}
	return resolved, nil
}

// ParseOpenAPI extracts deterministic operation inventory entries. Remote
// references are rejected so an uploaded definition cannot fetch outside the
// operator's approved scope.
func ParseOpenAPI(data []byte, origin string) ([]APIEndpoint, error) {
	if len(data) == 0 || len(data) > MaxOpenAPISpecBytes {
		return nil, fmt.Errorf("OpenAPI definition must be between 1 and %d bytes", MaxOpenAPISpecBytes)
	}
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("target origin must be an absolute HTTP(S) URL without credentials, query, or fragment")
		}
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("decode OpenAPI: %w", err)
		}
	}
	if version, ok := doc["openapi"].(string); ok {
		if !(strings.HasPrefix(version, "3.0.") || strings.HasPrefix(version, "3.1.")) {
			return nil, fmt.Errorf("OpenAPI version %q is unsupported; expected 3.0 or 3.1", version)
		}
	} else if version, ok := doc["swagger"].(string); !ok || version != "2.0" {
		return nil, fmt.Errorf("definition must be OpenAPI 3.0/3.1 or Swagger 2.0")
	}
	if err := validateLocalRefs(doc, doc, 0); err != nil {
		return nil, err
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenAPI definition must contain a paths object")
	}
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	verbs := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
	var out []APIEndpoint
	for _, path := range pathNames {
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("OpenAPI path %q must start with '/'", path)
		}
		raw := paths[path]
		operations, err := resolveOpenAPIObject(doc, raw)
		if err != nil {
			return nil, fmt.Errorf("path %q: %w", path, err)
		}
		for _, method := range verbs {
			operationValue, ok := operations[strings.ToLower(method)]
			if !ok {
				continue
			}
			operation, err := resolveOpenAPIObject(doc, operationValue)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", method, path, err)
			}
			resolved, reason := openAPIOperationResolved(path, operations, operation, doc)
			eligible := resolved && (method == "GET" || method == "HEAD")
			if resolved && !eligible {
				reason = "operation method is not yet supported by the safe request adapter"
			}
			parameters, bodyRequired, bodyTypes, security, servers := openAPIInputMetadata(operations, operation, doc)
			operationID, _ := operation["operationId"].(string)
			if strings.TrimSpace(operationID) == "" {
				operationID = strings.ToLower(method) + " " + path
			}
			out = append(out, APIEndpoint{Method: method, Path: path, Origin: origin, OperationID: operationID, Source: "openapi", Resolved: resolved, Eligible: eligible, Reason: reason,
				Parameters: parameters, RequestBodyRequired: bodyRequired, RequestBodyContentTypes: bodyTypes, SecuritySchemes: security, SpecServers: servers})
		}
	}
	return out, nil
}

// MaterializeOpenAPIOperations applies only explicitly supplied values for
// declared operation parameters. It never guesses values or adds undeclared
// query parameters. RequestURL is runtime-only; Path remains the canonical
// OpenAPI template for stable operation identity and reporting.
func MaterializeOpenAPIOperations(endpoints []APIEndpoint, definitionID, applicationURL string, inputs []assessment.APIOperationInput) []APIEndpoint {
	byOperation := make(map[string]assessment.APIOperationInput, len(inputs))
	for _, input := range inputs {
		if input.DefinitionID == definitionID {
			byOperation[input.OperationID] = input
		}
	}
	out := append([]APIEndpoint(nil), endpoints...)
	for i := range out {
		endpoint := &out[i]
		endpoint.DefinitionID = definitionID
		input, hasInput := byOperation[endpoint.OperationID]
		providedPath, providedQuery := map[string]string{}, map[string]string{}
		if hasInput {
			providedPath, providedQuery = input.PathParams, input.Query
		}
		pathParams := map[string]bool{}
		concretePath := regexp.MustCompile(`\{([^{}]+)\}`).ReplaceAllStringFunc(endpoint.Path, func(token string) string {
			name := strings.TrimSuffix(strings.TrimPrefix(token, "{"), "}")
			pathParams[name] = true
			value, ok := providedPath[name]
			if !ok || value == "" {
				endpoint.MissingInputs = append(endpoint.MissingInputs, "path:"+name)
				return token
			}
			if strings.ContainsAny(value, "/\\?#%\r\n\x00") || value == "." || value == ".." {
				endpoint.MissingInputs = append(endpoint.MissingInputs, "invalid path:"+name)
				return token
			}
			return url.PathEscape(value)
		})
		for name := range providedPath {
			if !pathParams[name] {
				endpoint.MissingInputs = append(endpoint.MissingInputs, "unexpected path parameter:"+name)
			}
		}
		queryParams := map[string]APIParameter{}
		for _, parameter := range endpoint.Parameters {
			if parameter.Location == "query" {
				queryParams[parameter.Name] = parameter
				if parameter.Required {
					if value, ok := providedQuery[parameter.Name]; !ok || value == "" {
						endpoint.MissingInputs = append(endpoint.MissingInputs, "query:"+parameter.Name)
					}
				}
			} else if parameter.Required && parameter.Location != "path" {
				endpoint.MissingInputs = append(endpoint.MissingInputs, parameter.Location+":"+parameter.Name)
			}
		}
		query := url.Values{}
		for name, value := range providedQuery {
			if _, declared := queryParams[name]; !declared {
				endpoint.MissingInputs = append(endpoint.MissingInputs, "unexpected query parameter:"+name)
				continue
			}
			query.Set(name, value)
		}
		sort.Strings(endpoint.MissingInputs)
		endpoint.MissingInputs = compactStrings(endpoint.MissingInputs)
		if len(endpoint.MissingInputs) > 0 {
			endpoint.Resolved, endpoint.Eligible = false, false
			endpoint.Reason = "required operation inputs are missing or do not match the definition: " + strings.Join(endpoint.MissingInputs, ", ")
			continue
		}
		if strings.Contains(concretePath, "{") || strings.Contains(concretePath, "}") {
			endpoint.Resolved, endpoint.Eligible = false, false
			endpoint.Reason = "path parameters have no supplied values"
			continue
		}
		inputGap := strings.HasPrefix(endpoint.Reason, "path parameters have no supplied values") || strings.HasPrefix(endpoint.Reason, "required parameter value is not materialized")
		if !endpoint.Resolved && !inputGap {
			continue
		}
		if strings.HasPrefix(endpoint.Reason, "request body needs") {
			continue
		}
		if endpoint.Method != "GET" && endpoint.Method != "HEAD" {
			endpoint.Resolved, endpoint.Eligible = true, false
			endpoint.Reason = "operation method is not yet supported by the safe request adapter"
			continue
		}
		materialized := *endpoint
		materialized.Path = concretePath
		// Required values have just been validated; join only the concrete path.
		materialized.Parameters = nil
		materialized.Resolved, materialized.Eligible, materialized.Reason = true, true, ""
		requestURL, err := apiEndpointURL(applicationURL, materialized)
		if err != nil {
			endpoint.Resolved, endpoint.Eligible, endpoint.Reason = false, false, err.Error()
			continue
		}
		parsed, err := url.Parse(requestURL)
		if err != nil {
			endpoint.Resolved, endpoint.Eligible, endpoint.Reason = false, false, "materialized request URL is invalid"
			continue
		}
		parsed.RawQuery = query.Encode()
		endpoint.RequestURL = parsed.String()
		endpoint.Resolved, endpoint.Eligible, endpoint.Reason = true, true, ""
	}
	return out
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func openAPIInputMetadata(pathItem, operation, root map[string]any) ([]APIParameter, bool, []string, []string, []string) {
	parametersByKey := map[string]APIParameter{}
	for _, listValue := range []any{pathItem["parameters"], operation["parameters"]} {
		list, _ := listValue.([]any)
		for _, raw := range list {
			parameter, err := resolveOpenAPIObject(root, raw)
			if err != nil {
				continue
			}
			name, _ := parameter["name"].(string)
			location, _ := parameter["in"].(string)
			if name == "" || location == "" {
				continue
			}
			required, _ := parameter["required"].(bool)
			schemaType := ""
			if schema, err := resolveOpenAPIObject(root, parameter["schema"]); err == nil {
				schemaType, _ = schema["type"].(string)
			}
			if schemaType == "" {
				schemaType, _ = parameter["type"].(string) // Swagger 2.0
			}
			key := strings.ToLower(location) + "\x00" + name
			prior := parametersByKey[key]
			parametersByKey[key] = APIParameter{Name: name, Location: location, Required: prior.Required || required, SchemaType: schemaType}
		}
	}
	parameters := make([]APIParameter, 0, len(parametersByKey))
	for _, parameter := range parametersByKey {
		parameters = append(parameters, parameter)
	}
	sort.Slice(parameters, func(i, j int) bool {
		if parameters[i].Location == parameters[j].Location {
			return parameters[i].Name < parameters[j].Name
		}
		return parameters[i].Location < parameters[j].Location
	})
	bodyRequired, bodyTypes := false, []string{}
	if body, err := resolveOpenAPIObject(root, operation["requestBody"]); err == nil {
		bodyRequired, _ = body["required"].(bool)
		if content, ok := body["content"].(map[string]any); ok {
			for contentType := range content {
				bodyTypes = append(bodyTypes, contentType)
			}
		}
	} else {
		for _, parameter := range parameters {
			if parameter.Location == "body" || parameter.Location == "formData" {
				bodyRequired = bodyRequired || parameter.Required
			}
		}
	}
	sort.Strings(bodyTypes)
	securitySource := root["security"]
	if value, exists := operation["security"]; exists {
		securitySource = value
	}
	securitySet := map[string]bool{}
	if requirements, ok := securitySource.([]any); ok {
		for _, raw := range requirements {
			if requirement, ok := raw.(map[string]any); ok {
				for name := range requirement {
					securitySet[name] = true
				}
			}
		}
	}
	security := make([]string, 0, len(securitySet))
	for name := range securitySet {
		security = append(security, name)
	}
	sort.Strings(security)
	servers := []string{}
	if value, exists := operation["servers"]; exists {
		servers = openAPIServerURLs(value)
	} else if value, exists := pathItem["servers"]; exists {
		servers = openAPIServerURLs(value)
	} else if value, exists := root["servers"]; exists {
		servers = openAPIServerURLs(value)
	}
	if len(servers) == 0 {
		if host, ok := root["host"].(string); ok && host != "" { // Swagger 2.0
			scheme := "https"
			if schemes, ok := root["schemes"].([]any); ok && len(schemes) > 0 {
				if first, ok := schemes[0].(string); ok && first != "" {
					scheme = first
				}
			}
			basePath, _ := root["basePath"].(string)
			servers = []string{scheme + "://" + host + basePath}
		}
	}
	return parameters, bodyRequired, bodyTypes, security, servers
}

func openAPIServerURLs(value any) []string {
	list, _ := value.([]any)
	seen := map[string]bool{}
	var out []string
	for _, raw := range list {
		server, _ := raw.(map[string]any)
		serverURL, _ := server["url"].(string)
		serverURL = strings.TrimSpace(serverURL)
		if serverURL != "" && !seen[serverURL] {
			seen[serverURL] = true
			out = append(out, serverURL)
		}
	}
	sort.Strings(out)
	return out
}

func validateLocalRefs(value, root any, depth int) error {
	if depth > 128 {
		return fmt.Errorf("OpenAPI structure exceeds reference validation depth")
	}
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if key == "$ref" {
				ref, ok := child.(string)
				if !ok || !strings.HasPrefix(ref, "#/") {
					return fmt.Errorf("remote or unsupported $ref is not allowed")
				}
				if _, ok := resolveJSONPointer(root, strings.TrimPrefix(ref, "#")); !ok {
					return fmt.Errorf("OpenAPI $ref %q does not resolve", ref)
				}
			}
			if err := validateLocalRefs(child, root, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := validateLocalRefs(child, root, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveJSONPointer(root any, pointer string) (any, bool) {
	current := root
	for _, raw := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = node[part]
			if !ok {
				return nil, false
			}
		case []any:
			var index int
			if _, err := fmt.Sscanf(part, "%d", &index); err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func resolveOpenAPIObject(root map[string]any, value any) (map[string]any, error) {
	seen := map[string]bool{}
	for depth := 0; depth < 128; depth++ {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("OpenAPI reference is not an object")
		}
		ref, hasRef := object["$ref"].(string)
		if !hasRef {
			return object, nil
		}
		if !strings.HasPrefix(ref, "#/") || seen[ref] {
			return nil, fmt.Errorf("cyclic or non-local OpenAPI reference %q", ref)
		}
		seen[ref] = true
		resolved, ok := resolveJSONPointer(root, strings.TrimPrefix(ref, "#"))
		if !ok {
			return nil, fmt.Errorf("unresolved OpenAPI reference %q", ref)
		}
		value = resolved
	}
	return nil, fmt.Errorf("OpenAPI reference chain is too deep")
}

func openAPIOperationResolved(path string, pathItem, operation, root map[string]any) (bool, string) {
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return false, "path parameters have no supplied values"
	}
	for _, params := range []any{pathItem["parameters"], operation["parameters"]} {
		list, _ := params.([]any)
		for _, raw := range list {
			param, err := resolveOpenAPIObject(root, raw)
			if err != nil {
				return false, "parameter reference cannot be resolved safely: " + err.Error()
			}
			if required, _ := param["required"].(bool); required {
				return false, "required parameter value is not materialized by this adapter"
			}
		}
	}
	if operation["requestBody"] != nil {
		return false, "request body needs an explicit safe request example"
	}
	return true, ""
}

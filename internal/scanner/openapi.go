package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const MaxOpenAPISpecBytes = 5 << 20

type APIEndpoint struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Origin   string `json:"origin,omitempty"`
	TargetID string `json:"target_id,omitempty"`
	Source   string `json:"source"`
	Resolved bool   `json:"resolved"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

type APIEndpointResult struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func apiEndpointURL(applicationURL string, endpoint APIEndpoint) (string, error) {
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
		operations, _ := raw.(map[string]any)
		for _, method := range verbs {
			operationValue, ok := operations[strings.ToLower(method)]
			if !ok {
				continue
			}
			operation, _ := operationValue.(map[string]any)
			resolved, reason := openAPIOperationResolved(path, operations, operation)
			eligible := resolved && (method == "GET" || method == "HEAD")
			if resolved && !eligible {
				reason = "operation method is not yet supported by the safe request adapter"
			}
			out = append(out, APIEndpoint{Method: method, Path: path, Origin: origin, Source: "openapi", Resolved: resolved, Eligible: eligible, Reason: reason})
		}
	}
	return out, nil
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

func openAPIOperationResolved(path string, pathItem, operation map[string]any) (bool, string) {
	if strings.Contains(path, "{") || strings.Contains(path, "}") {
		return false, "path parameters have no supplied values"
	}
	for _, params := range []any{pathItem["parameters"], operation["parameters"]} {
		list, _ := params.([]any)
		for _, raw := range list {
			param, _ := raw.(map[string]any)
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

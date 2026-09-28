package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const MaxOpenAPISpecBytes = 5 << 20

type APIEndpoint struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Origin   string `json:"origin,omitempty"`
	Source   string `json:"source"`
	Resolved bool   `json:"resolved"`
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
	if containsRemoteRef(doc) {
		return nil, fmt.Errorf("remote $ref is not allowed")
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
			if _, ok := operations[strings.ToLower(method)]; ok {
				out = append(out, APIEndpoint{Method: method, Path: path, Origin: origin, Source: "openapi", Resolved: true})
			}
		}
	}
	return out, nil
}

func containsRemoteRef(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if key == "$ref" {
				ref, ok := child.(string)
				if !ok || !strings.HasPrefix(ref, "#") {
					return true
				}
			}
			if containsRemoteRef(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if containsRemoteRef(child) {
				return true
			}
		}
	}
	return false
}

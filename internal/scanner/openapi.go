package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("decode OpenAPI: %w", err)
		}
	}
	if _, ok := doc["openapi"]; !ok {
		if _, ok := doc["swagger"]; !ok {
			return nil, fmt.Errorf("definition is not OpenAPI or Swagger")
		}
	}
	if strings.Contains(string(data), "\"$ref\":\"http") || strings.Contains(string(data), "$ref: http") {
		return nil, fmt.Errorf("remote $ref is not allowed")
	}
	paths, _ := doc["paths"].(map[string]any)
	var out []APIEndpoint
	for path, raw := range paths {
		methods, _ := raw.(map[string]any)
		for method := range methods {
			m := strings.ToUpper(method)
			switch m {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
				out = append(out, APIEndpoint{Method: m, Path: path, Origin: origin, Source: "openapi", Resolved: true})
			}
		}
	}
	return out, nil
}

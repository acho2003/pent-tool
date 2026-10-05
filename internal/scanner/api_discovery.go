package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

var schemaProbePaths = []string{"/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v3/api-docs", "/api-docs"}

const graphQLIntrospection = `query XalgorixSchema { __schema { queryType { name fields { name args { name type { kind name ofType { kind name } } } type { kind name ofType { kind name } } } } mutationType { name fields { name } } } }`

// ParseAPIDefinition supports existing OpenAPI uploads and validated GraphQL SDL.
func ParseAPIDefinition(data []byte, origin string) ([]APIEndpoint, error) {
	if len(data) == 0 || len(data) > MaxOpenAPISpecBytes {
		return nil, fmt.Errorf("API definition size is invalid")
	}
	if endpoints, err := ParseOpenAPI(data, origin); err == nil {
		return endpoints, nil
	}
	schema, err := gqlparser.LoadSchema(&ast.Source{Name: "uploaded.graphql", Input: string(data)})
	if err != nil || schema.Query == nil {
		return nil, fmt.Errorf("invalid OpenAPI or GraphQL schema")
	}
	endpoint := origin
	if u, e := url.Parse(origin); e == nil && u.Path == "/" {
		u.Path = "/graphql"
		endpoint = u.String()
	}
	var out []APIEndpoint
	for _, root := range []*ast.Definition{schema.Query, schema.Mutation} {
		if root == nil {
			continue
		}
		for _, f := range root.Fields {
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			operation := APIEndpoint{Method: "GET", Origin: origin, OperationID: "query " + f.Name, Source: "graphql", Resolved: true, Eligible: root == schema.Query}
			if u, e := url.Parse(endpoint); e == nil {
				operation.Path = u.Path
			}
			for _, arg := range f.Arguments {
				operation.Parameters = append(operation.Parameters, APIParameter{Name: arg.Name, Location: "graphql", Required: arg.Type.NonNull, SchemaType: arg.Type.Name()})
				if arg.Type.NonNull && arg.DefaultValue == nil {
					operation.Resolved, operation.Eligible = false, false
					operation.MissingInputs = append(operation.MissingInputs, arg.Name)
				}
			}
			selection := ""
			if def := schema.Types[f.Type.Name()]; def != nil && (def.Kind == ast.Object || def.Kind == ast.Interface || def.Kind == ast.Union) {
				selection = " { __typename }"
			}
			if root == schema.Mutation {
				operation.Method = "POST"
				operation.OperationID = "mutation " + f.Name
				operation.Reason = "mutation requires operation approval and fixtures"
			} else {
				query := "query { " + f.Name + selection + " }"
				u, e := url.Parse(endpoint)
				if e == nil {
					q := u.Query()
					q.Set("query", query)
					u.RawQuery = q.Encode()
					operation.RequestURL = u.String()
				}
				if !operation.Resolved {
					operation.Reason = "GraphQL operation requires supplied arguments"
				}
			}
			out = append(out, operation)
		}
	}
	return out, nil
}

func DiscoverAPIs(ctx context.Context, req Request, cfg Config, surface *AttackSurface) []APIEndpoint {
	if req.AppScope == nil || surface == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	candidates := []string{}
	for _, o := range req.AppScope.Origins() {
		for _, p := range schemaProbePaths {
			candidates = append(candidates, o.Origin()+p)
		}
		candidates = append(candidates, o.Origin()+"/graphql")
	}
	for _, ep := range surface.Endpoints {
		lower := strings.ToLower(ep.Path)
		if strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") || strings.Contains(lower, "graphql") {
			candidates = append(candidates, ep.URL)
		}
	}
	seen := map[string]bool{}
	var endpoints []APIEndpoint
	for _, raw := range candidates {
		if seen[raw] {
			continue
		}
		seen[raw] = true
		if len(seen) > 32 {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "API definition probe limit reached")
			break
		}
		if err := browserRequestAllowed(req, cfg, "GET", raw); err != nil {
			continue
		}
		if err := cfg.Budget.Wait(ctx); err != nil {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "API discovery time budget exhausted")
			break
		}
		u, _ := url.Parse(raw)
		graphql := strings.Contains(strings.ToLower(u.Path), "graphql")
		probeURL := raw
		if graphql {
			q := u.Query()
			q.Set("query", graphQLIntrospection)
			u.RawQuery = q.Encode()
			probeURL = u.String()
		}
		request, _ := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		bound, _ := assessment.ParseApprovedOrigin("", req.Target)
		o, _ := assessment.ParseApprovedOrigin("", raw)
		if bound.Scheme == o.Scheme && bound.Host == o.Host && bound.Port == o.Port {
			for _, h := range strings.Split(req.TargetAuth, "\n") {
				name, value, ok := strings.Cut(h, ":")
				if ok {
					request.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
				}
			}
		}
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, MaxOpenAPISpecBytes+1))
		response.Body.Close()
		if err != nil || len(data) > MaxOpenAPISpecBytes || response.StatusCode != 200 {
			continue
		}
		kind := "openapi"
		var discovered []APIEndpoint
		if graphql {
			kind = "graphql"
			discovered, err = graphQLIntrospectionEndpoints(data, raw)
		} else {
			discovered, err = ParseOpenAPI(data, o.Origin())
		}
		if err != nil {
			if graphql {
				surface.Definitions = append(surface.Definitions, InventoryDefinition{ID: inventoryID(raw), Kind: kind, URL: raw, State: "unavailable", Reason: "introspection disabled or schema unavailable"})
			}
			continue
		}
		path := filepath.Join(req.ScanDir, "api-discovery", inventoryID(raw)+".json")
		if err := storage.EnsureSecureDir(filepath.Dir(path)); err != nil {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "could not persist discovered schema")
			continue
		}
		if err := storage.WriteAtomic(path, data); err != nil {
			surface.DiscoveryGaps = append(surface.DiscoveryGaps, "could not persist discovered schema")
			continue
		}
		surface.Definitions = append(surface.Definitions, InventoryDefinition{ID: inventoryID(raw, string(data)), Kind: kind, URL: raw, State: "validated", EvidenceRef: path})
		for i := range discovered {
			discovered[i].DefinitionID = inventoryID(raw, string(data))
			discovered[i].RequestBodyContentTypes = append(discovered[i].RequestBodyContentTypes, "application/json")
		}
		endpoints = append(endpoints, discovered...)
	}
	return endpoints
}

func graphQLIntrospectionEndpoints(data []byte, endpoint string) ([]APIEndpoint, error) {
	type field struct {
		Name string `json:"name"`
		Args []struct {
			Name string `json:"name"`
			Type struct {
				Kind string `json:"kind"`
			} `json:"type"`
		} `json:"args"`
		Type struct {
			Kind   string `json:"kind"`
			OfType *struct {
				Kind string `json:"kind"`
			} `json:"ofType"`
		} `json:"type"`
	}
	var result struct {
		Data struct {
			Schema *struct {
				Query *struct {
					Fields []field `json:"fields"`
				} `json:"queryType"`
				Mutation *struct {
					Fields []field `json:"fields"`
				} `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Data.Schema == nil {
		return nil, fmt.Errorf("GraphQL schema unavailable")
	}
	var out []APIEndpoint
	add := func(fields []field, mutation bool) {
		for _, f := range fields {
			u, err := url.Parse(endpoint)
			if err != nil {
				continue
			}
			op := APIEndpoint{Method: "GET", Path: u.Path, Origin: u.Scheme + "://" + u.Host, Source: "graphql", OperationID: "query " + f.Name, Resolved: true, Eligible: !mutation}
			for _, a := range f.Args {
				required := a.Type.Kind == "NON_NULL"
				op.Parameters = append(op.Parameters, APIParameter{Name: a.Name, Location: "graphql", Required: required})
				if required {
					op.Resolved, op.Eligible = false, false
					op.MissingInputs = append(op.MissingInputs, a.Name)
				}
			}
			if mutation {
				op.Method = "POST"
				op.OperationID = "mutation " + f.Name
				op.Reason = "mutation requires operation approval and fixtures"
			} else {
				selection := ""
				kind := f.Type.Kind
				if f.Type.OfType != nil {
					kind = f.Type.OfType.Kind
				}
				if kind == "OBJECT" || kind == "INTERFACE" || kind == "UNION" || kind == "LIST" {
					selection = " { __typename }"
				}
				q := u.Query()
				q.Set("query", "query { "+f.Name+selection+" }")
				u.RawQuery = q.Encode()
				op.RequestURL = u.String()
				if !op.Resolved {
					op.Reason = "GraphQL operation requires supplied arguments"
				}
			}
			out = append(out, op)
		}
	}
	if result.Data.Schema.Query != nil {
		add(result.Data.Schema.Query.Fields, false)
	}
	if result.Data.Schema.Mutation != nil {
		add(result.Data.Schema.Mutation.Fields, true)
	}
	return out, nil
}

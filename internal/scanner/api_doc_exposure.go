package scanner

import (
	"bytes"
	"context"
	"net/http"
	"strings"
)

// apiDocsCatalogVersion is part of the plan fingerprint. Keep it small.
const apiDocsCatalogVersion = "api-docs-v1"

type apiDocExposureRunner struct{}

func (apiDocExposureRunner) Name() string { return "api-docs" }
func (apiDocExposureRunner) Descriptor() Descriptor {
	return Descriptor{Name: "api-docs", Summary: "Bounded read-only checks for anonymously exposed API documentation (Swagger/OpenAPI/Redoc/GraphQL)", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (apiDocExposureRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runExposureCatalog(ctx, req, cfg, emit, "api-docs", apiDocsCatalogVersion, "exposed API documentation", apiDocCatalog, classifyAPIDocExposure)
}

// apiDocCatalog probes the well-known locations where API documentation and
// specifications are served. An anonymously reachable Swagger UI, OpenAPI spec,
// Redoc page or GraphQL playground hands an attacker the full API surface
// (operations, parameters, auth scheme), so each is reported as information
// disclosure. Every probe is a single read-only GET; the body is read only to
// confirm the document's signature and is never written anywhere.
var apiDocCatalog = []exposureCheck{
	// Swagger UI (Springfox/Springdoc and generic).
	{ID: "swagger-ui", Path: "/swagger", Purpose: "Anonymously accessible Swagger UI"},
	{ID: "swagger-ui-html", Path: "/swagger-ui.html", Purpose: "Anonymously accessible Swagger UI"},
	{ID: "swagger-ui-index", Path: "/swagger-ui/index.html", Purpose: "Anonymously accessible Swagger UI"},
	{ID: "swagger-index", Path: "/swagger/index.html", Purpose: "Anonymously accessible Swagger UI"},
	// OpenAPI / Swagger specification documents.
	{ID: "openapi-json", Path: "/openapi.json", Purpose: "Anonymously accessible OpenAPI specification"},
	{ID: "swagger-json", Path: "/swagger.json", Purpose: "Anonymously accessible Swagger specification"},
	{ID: "swagger-v1-json", Path: "/swagger/v1/swagger.json", Purpose: "Anonymously accessible Swagger specification"},
	{ID: "springdoc-v3", Path: "/v3/api-docs", Purpose: "Anonymously accessible OpenAPI specification"},
	{ID: "springfox-v2", Path: "/v2/api-docs", Purpose: "Anonymously accessible Swagger specification"},
	{ID: "api-docs", Path: "/api-docs", Purpose: "Anonymously accessible API documentation"},
	// NestJS @nestjs/swagger conventions.
	{ID: "nest-docs", Path: "/docs", Purpose: "Anonymously accessible API documentation"},
	{ID: "nest-docs-json", Path: "/docs-json", Purpose: "Anonymously accessible OpenAPI specification"},
	{ID: "nest-documentation", Path: "/documentation", Purpose: "Anonymously accessible API documentation"},
	{ID: "nest-documentation-json", Path: "/documentation-json", Purpose: "Anonymously accessible OpenAPI specification"},
	{ID: "nest-api-docs-json", Path: "/api/docs-json", Purpose: "Anonymously accessible OpenAPI specification"},
	// Redoc.
	{ID: "redoc", Path: "/redoc", Purpose: "Anonymously accessible Redoc API documentation"},
	// GraphQL interactive consoles.
	{ID: "graphql", Path: "/graphql", Purpose: "Anonymously accessible GraphQL console"},
	{ID: "graphiql", Path: "/graphiql", Purpose: "Anonymously accessible GraphiQL console"},
	{ID: "graphql-playground", Path: "/playground", Purpose: "Anonymously accessible GraphQL Playground"},
}

// classifyAPIDocExposure confirms a probed response actually serves API
// documentation before reporting it, matching on the document's signature rather
// than the path alone (a single-page app answers 200 with HTML for every path).
// The verdict never carries the body, so no endpoint data is written to the
// findings artifact.
func classifyAPIDocExposure(_ exposureCheck, resp *http.Response, body []byte) exposureVerdict {
	if resp.StatusCode != http.StatusOK {
		return exposureVerdict{}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return exposureVerdict{}
	}
	text := string(trimmed)
	lower := strings.ToLower(text)
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	leak := func(sev, title string) exposureVerdict {
		return exposureVerdict{Classification: "api_documentation_exposed", Severity: sev, Title: title}
	}

	// JSON documents: an OpenAPI/Swagger spec, or a GraphQL introspection result.
	if strings.HasPrefix(text, "{") || strings.Contains(ct, "json") {
		if (strings.Contains(lower, "\"swagger\"") || strings.Contains(lower, "\"openapi\"")) && strings.Contains(lower, "\"paths\"") {
			return leak("low", "Anonymously accessible OpenAPI/Swagger specification")
		}
		if strings.Contains(lower, "__schema") && (strings.Contains(lower, "querytype") || strings.Contains(lower, "\"types\"")) {
			return leak("medium", "Anonymously accessible GraphQL introspection")
		}
		return exposureVerdict{}
	}

	// HTML interactive documentation. Match on framework-specific markers so a
	// generic 200 HTML catch-all page is not misreported.
	switch {
	case strings.Contains(lower, "swaggeruibundle"), strings.Contains(lower, "swagger-ui-bundle"),
		strings.Contains(lower, "swagger-ui-init"), (strings.Contains(lower, "swagger-ui") && strings.Contains(text, "<")):
		return leak("medium", "Anonymously accessible Swagger UI")
	case strings.Contains(lower, "redoc.init("), strings.Contains(lower, "<redoc"), strings.Contains(lower, "redoc-container"):
		return leak("medium", "Anonymously accessible Redoc API documentation")
	case strings.Contains(lower, "graphiql"), strings.Contains(lower, "graphql playground"), strings.Contains(lower, "graphql-playground"):
		return leak("medium", "Anonymously accessible GraphQL console")
	}
	return exposureVerdict{}
}

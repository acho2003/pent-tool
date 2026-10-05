package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// Browser GraphQL reads commonly use POST. Only an explicit, single JSON
// GraphQL query is eligible; opaque persisted queries, batches, writes and
// subscriptions stay blocked. This does not relax active adapter policy.
func browserDiscoveryRequestAllowed(req Request, cfg Config, method, rawURL, contentType string, body []byte) error {
	if method != http.MethodPost {
		return browserRequestAllowed(req, cfg, method, rawURL)
	}
	// Check URL-carried GraphQL operations too; a body must not hide a
	// mutation supplied in the URL. Then enforce the actual POST exclusion.
	if err := browserRequestAllowed(req, cfg, http.MethodGet, rawURL); err != nil {
		return err
	}
	// Reuse origin, exclusion and process guards without treating POST as GET.
	if req.AppScope == nil {
		return fmt.Errorf("approved scope required")
	}
	if ok, why := req.AppScope.Allows(rawURL); !ok {
		return fmt.Errorf("%s", why)
	}
	if excluded, why := req.AppScope.Excluded(method, rawURL); excluded {
		return fmt.Errorf("excluded: %s", why)
	}
	if cfg.ScopeGuard != nil {
		if blocked, why := cfg.ScopeGuard(rawURL, nil); blocked {
			return fmt.Errorf("%s", why)
		}
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(body) > 2<<20 {
		return fmt.Errorf("browser POST requires an explicit read-only GraphQL JSON operation")
	}
	var payload struct {
		Query         string                     `json:"query"`
		OperationName string                     `json:"operationName"`
		Variables     map[string]json.RawMessage `json:"variables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Query == "" || !json.Valid(body) {
		return fmt.Errorf("browser POST requires a single explicit GraphQL query")
	}
	document, err := parser.ParseQuery(&ast.Source{Input: payload.Query})
	if err != nil || len(document.Operations) == 0 {
		return fmt.Errorf("GraphQL query is invalid")
	}
	selected := 0
	for _, operation := range document.Operations {
		// Reject mixed documents too: a later operationName rewrite must never
		// turn an accepted discovery body into an approved mutation.
		if operation.Operation != ast.Query {
			return fmt.Errorf("GraphQL writes require explicit operation approval")
		}
		if payload.OperationName == "" || operation.Name == payload.OperationName {
			selected++
		}
	}
	if selected != 1 {
		return fmt.Errorf("GraphQL query selection is missing or ambiguous")
	}
	return nil
}

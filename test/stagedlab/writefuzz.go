package stagedlab

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// A JSON write surface for the opt-in API write-fuzzing suite. Every handler
// records the method so the driver can prove which generated writes the
// gateway admitted. The /wf/danger route is excluded from the assessment and
// must never be reached.
var writeFuzzHits atomic.Int64

// WriteFuzzMethods returns the distinct HTTP methods the write-fuzz surface
// received, for the staged driver's control API.
func (l *Lab) writeFuzzMethods() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.writeFuzzMethodSet))
	for method := range l.writeFuzzMethodSet {
		out = append(out, method)
	}
	return out
}

func (l *Lab) recordWriteFuzz(method string) {
	writeFuzzHits.Add(1)
	l.mu.Lock()
	if l.writeFuzzMethodSet == nil {
		l.writeFuzzMethodSet = map[string]bool{}
	}
	l.writeFuzzMethodSet[method] = true
	l.mu.Unlock()
}

func (l *Lab) registerWriteFuzzRoutes(mux *http.ServeMux) {
	ok := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			l.recordWriteFuzz(r.Method)
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "wf-1"})
		}
	}
	mux.HandleFunc("POST "+PathPrefix+"api/wf", ok(http.StatusCreated))
	mux.HandleFunc("PUT "+PathPrefix+"api/wf/{id}", ok(http.StatusOK))
	mux.HandleFunc("PATCH "+PathPrefix+"api/wf/{id}", ok(http.StatusOK))
	mux.HandleFunc("DELETE "+PathPrefix+"api/wf/{id}", ok(http.StatusOK))
	// An excluded destructive route: any contact is a violation.
	mux.HandleFunc("DELETE "+PathPrefix+"api/wf/danger", func(w http.ResponseWriter, r *http.Request) {
		l.recordWriteFuzz("DANGER")
		w.WriteHeader(http.StatusOK)
	})
}

// WriteFuzzSpec is the OpenAPI document for the write-fuzz surface (all
// application/json), uploaded by the staged writefuzz suite.
func writeFuzzSpec() string {
	body := map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{
		"type": "object", "properties": map[string]any{"name": map[string]string{"type": "string"}, "count": map[string]string{"type": "integer"}},
	}}}}
	idParam := []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}}
	doc := map[string]any{
		"openapi": "3.0.3", "info": map[string]string{"title": "Staged write-fuzz surface", "version": "1"},
		"paths": map[string]any{
			"/api/wf": map[string]any{
				"post": map[string]any{"operationId": "createWF", "requestBody": body, "responses": okResponse()},
			},
			"/api/wf/{id}": map[string]any{
				"put":    map[string]any{"operationId": "putWF", "parameters": idParam, "requestBody": body, "responses": okResponse()},
				"patch":  map[string]any{"operationId": "patchWF", "parameters": idParam, "requestBody": body, "responses": okResponse()},
				"delete": map[string]any{"operationId": "deleteWF", "parameters": idParam, "responses": okResponse()},
			},
			"/api/wf/danger": map[string]any{
				"delete": map[string]any{"operationId": "dangerWF", "responses": okResponse()},
			},
		},
	}
	out, _ := json.Marshal(doc)
	return string(out)
}

func okResponse() map[string]any {
	return map[string]any{"200": map[string]string{"description": "ok"}, "201": map[string]string{"description": "created"}}
}

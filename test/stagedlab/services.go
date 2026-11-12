package stagedlab

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Microservice lab: an auth service that issues bearer JWTs from a JSON login
// API, two services that accept only those tokens, and a stray service that is
// an assessment target but must never receive a token. Every value is
// synthetic.
const (
	ServiceUser       = "qa@lab.test"
	ServicePassword   = "lab-svc-password"
	ServiceIdentity   = "svc-user"
	ServiceLoginPath  = "/api/auth/login"
	ServiceLogoutPath = "/api/auth/logout"
	// ServiceTokenLifetime is long enough that a staged run never needs renewal;
	// renewal is covered by unit tests.
	ServiceTokenLifetime = 2 * time.Hour
)

// ServiceOrigins lists the recorder origin names of the microservice lab.
var ServiceOrigins = []string{"svc-auth", "svc-orders", "svc-reports", "svc-stray"}

func serviceJWT(serial int) string {
	random := make([]byte, 12)
	_, _ = rand.Read(random)
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]any{"sub": ServiceUser, "jti": hex.EncodeToString(random), "n": serial, "exp": time.Now().Add(ServiceTokenLifetime).Unix()})
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString(payload) + ".bGFiLXNpZ25hdHVyZQ"
}

// bearerToken returns the bearer token a request carries, if any.
func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if token, ok := strings.CutPrefix(value, "Bearer "); ok {
		return strings.TrimSpace(token)
	}
	return ""
}

// serviceAuthorized reports whether the request carries a token the auth
// service issued.
func (l *Lab) serviceAuthorized(r *http.Request) bool {
	token := bearerToken(r)
	if token == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.expired && l.sessions[token] == ServiceIdentity
}

// ServiceLogins is how many times the auth service issued a token.
func (l *Lab) ServiceLogins() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.serviceLogins
}

// ServiceTokens returns every token the auth service issued, for leak checks.
func (l *Lab) ServiceTokens() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.serviceTokens...)
}

func protectedJSON(l *Lab, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.serviceAuthorized(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"statusCode":401,"message":"Unauthorized"}`))
			return
		}
		writeJSON(w, body)
	}
}

// ServiceAuthHandler is the auth service: JSON login, a protected profile and a
// NestJS-style /api-json schema.
func (l *Lab) ServiceAuthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<h1>Auth service</h1><a href="/api/auth/me">profile</a>`)
	})
	mux.HandleFunc("POST "+ServiceLoginPath, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || !secureEqual(body["email"], ServiceUser) || !secureEqual(body["password"], ServicePassword) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"statusCode":401,"message":"Invalid credentials"}`))
			return
		}
		l.mu.Lock()
		if l.expired {
			l.mu.Unlock()
			http.Error(w, "login disabled", http.StatusServiceUnavailable)
			return
		}
		l.serviceLogins++
		token := serviceJWT(l.serviceLogins)
		l.sessions[token] = ServiceIdentity
		l.sessionLogin[token] = l.serviceLogins
		l.serviceTokens = append(l.serviceTokens, token)
		l.mu.Unlock()
		writeJSON(w, map[string]any{"data": map[string]any{"accessToken": token, "user": map[string]string{"email": ServiceUser}}})
	})
	mux.HandleFunc("POST "+ServiceLogoutPath, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /api/auth/me", protectedJSON(l, map[string]string{"email": ServiceUser, "role": "qa"}))
	mux.HandleFunc("GET /api-json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(serviceSpec("Auth service", map[string]any{
			"/api/auth/me":     map[string]any{"get": op("getProfile", nil)},
			"/api/auth/logout": map[string]any{"post": op("logout", nil)},
		})))
	})
	return mux
}

// ServiceOrdersHandler publishes its schema at the NestJS default /api-json.
func (l *Lab) ServiceOrdersHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<h1>Orders service</h1><a href="/api/orders">orders</a>`)
	})
	mux.HandleFunc("GET /api/orders", protectedJSON(l, map[string]any{"items": []map[string]string{{"id": "ord-1"}, {"id": "ord-2"}}}))
	mux.HandleFunc("GET /api/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		protectedJSON(l, map[string]string{"id": r.PathValue("id"), "status": "open"})(w, r)
	})
	mux.HandleFunc("GET /api/orders/search", protectedJSON(l, map[string]any{"items": []string{}}))
	mux.HandleFunc("GET /api-json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(serviceSpec("Orders service", map[string]any{
			"/api/orders":        map[string]any{"get": op("listOrders", nil)},
			"/api/orders/search": map[string]any{"get": op("searchOrders", []any{map[string]any{"name": "q", "in": "query", "required": false, "schema": map[string]string{"type": "string"}}})},
		})))
	})
	return mux
}

// ServiceReportsHandler publishes no schema; the suite uploads one.
func (l *Lab) ServiceReportsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { page(w, `<h1>Reports service</h1>`) })
	mux.HandleFunc("GET /api/reports", protectedJSON(l, map[string]any{"items": []string{}}))
	mux.HandleFunc("GET /api/reports/summary", protectedJSON(l, map[string]int{"total": 0}))
	return mux
}

// ServiceStrayHandler is an assessment target that is never bound to the token.
func (l *Lab) ServiceStrayHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<h1>Stray service</h1><a href="/status">status</a>`)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"status": "ok"}) })
	return mux
}

func op(id string, parameters []any) map[string]any {
	out := map[string]any{"operationId": id, "responses": map[string]any{"200": map[string]string{"description": "ok"}}}
	if parameters != nil {
		out["parameters"] = parameters
	}
	return out
}

func serviceSpec(title string, paths map[string]any) string {
	doc := map[string]any{"openapi": "3.0.0", "info": map[string]string{"title": title, "version": "1"}, "paths": paths}
	out, _ := json.Marshal(doc)
	return string(out)
}

// reportsSpec is the definition the suite uploads for the reports service.
func reportsSpec() string {
	return serviceSpec("Reports service", map[string]any{
		"/api/reports":         map[string]any{"get": op("listReports", nil)},
		"/api/reports/summary": map[string]any{"get": op("reportSummary", nil)},
	})
}

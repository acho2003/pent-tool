// Package stagedlab is a disposable, deterministic multi-origin web lab for the
// staged assessment acceptance tests. Every listener binds to loopback, all data
// is synthetic, and every request is recorded so tests can assert both what was
// reached and that nothing outside the approved boundary was contacted.
package stagedlab

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// PathPrefix is the approved path boundary on the primary origin.
	PathPrefix = "/app/"
	// OutsidePath lives on the primary origin but outside PathPrefix.
	OutsidePath = "/outside/secret"

	AdminUser     = "admin"
	AdminPassword = "lab-admin-password"
	AdminMarker   = "LAB_ADMIN_MARKER"
	ViewerUser    = "viewer"
	// ViewerPassword and the tokens are synthetic lab values only.
	ViewerPassword = "lab-viewer-password"
	ViewerMarker   = "LAB_VIEWER_MARKER"
	AdminToken     = "lab-admin-session"
	ViewerToken    = "lab-viewer-session"
	CookieName     = "lab_session"
	CSRFValue      = "lab-csrf-synthetic"

	// VariantCount is the number of distinct exact request variants linked from
	// the catalog page.
	VariantCount = 684
)

// Hit is one request observed by the lab.
type Hit struct {
	Origin   string `json:"origin"` // primary, secondary, alias
	Method   string `json:"method"`
	Path     string `json:"path"`
	RawQuery string `json:"raw_query"`
	Identity string `json:"identity"` // anonymous, admin or viewer
	// UserAgent identifies which tool produced the request.
	UserAgent string `json:"user_agent"`
	// Login is the 1-based number of the login that issued the session token the
	// request carried, or 0 when it carried none. Every login issues a new token, so
	// this shows whether authenticated traffic reused an older session.
	Login int    `json:"login"`
	Body  string `json:"body"`
}

// URL returns the path and query exactly as received.
func (h Hit) URL() string {
	if h.RawQuery == "" {
		return h.Path
	}
	return h.Path + "?" + h.RawQuery
}

// Lab owns the listeners and request log.
type Lab struct {
	Primary   *httptest.Server // HTTP, approved only below PathPrefix
	Secondary *httptest.Server // HTTPS, approved origin without introspection
	Alias     *httptest.Server // never approved; any contact is a violation
	DeadURL   string           // a closed loopback port

	// AliasURL is the public base URL of the unapproved alias origin. Pages link
	// and redirect to it so crawlers can be shown leaving the approved scope.
	AliasURL string
	// SecondaryURL is the public base URL of the second origin. It is linked
	// from the home page so it surfaces as a discovery candidate that must be
	// approved before any tool may contact it.
	SecondaryURL string

	mu           sync.Mutex
	sessions     map[string]string // issued session token -> identity
	sessionLogin map[string]int    // issued session token -> the login that created it (1-based)
	logins       int
	recordDelay  time.Duration // artificial latency for POST /api/records, set through the control API
	expired      bool          // when set, every session is treated as expired and logins are refused
	hits         []Hit
	resources    map[string]string
	nextID       int
}

// Start launches the lab and registers cleanup.
func Start(t testing.TB) *Lab {
	t.Helper()
	l := New()
	l.Primary = httptest.NewServer(l.PrimaryHandler())
	l.Secondary = httptest.NewTLSServer(l.SecondaryHandler())
	l.Alias = httptest.NewServer(l.AliasHandler())
	l.AliasURL = l.Alias.URL
	l.SecondaryURL = l.Secondary.URL
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.DeadURL = "http://" + listener.Addr().String() + "/"
	_ = listener.Close()
	t.Cleanup(func() {
		l.Primary.Close()
		l.Secondary.Close()
		l.Alias.Close()
	})
	return l
}

// New returns a lab with no listeners. Callers serve the Primary, Secondary and
// Alias handlers themselves and set AliasURL to the alias origin's public URL.
func New() *Lab {
	return &Lab{resources: map[string]string{}, sessions: map[string]string{}, sessionLogin: map[string]int{}}
}

// PrimaryHandler serves the HTTP origin approved below PathPrefix.
func (l *Lab) PrimaryHandler() http.Handler { return l.record("primary", l.primaryRoutes()) }

// SecondaryHandler serves the second approved origin (HTTPS when wrapped in TLS).
func (l *Lab) SecondaryHandler() http.Handler { return l.record("secondary", l.secondaryRoutes()) }

// AliasHandler serves the origin that must never be contacted.
func (l *Lab) AliasHandler() http.Handler {
	return l.record("alias", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "unapproved alias origin")
	}))
}

// ControlHandler exposes the recorder for out-of-process drivers. It is not
// linked from any page and is excluded from the request log.
func (l *Lab) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Lab-Control") != "local-only" {
				http.NotFound(w, r)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /hits", guard(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, l.Hits()) }))
	mux.HandleFunc("GET /forbidden", guard(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, l.Forbidden()) }))
	mux.HandleFunc("GET /resources", guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]int{"resources": l.Resources()})
	}))
	mux.HandleFunc("GET /specs/{name}", guard(func(w http.ResponseWriter, r *http.Request) {
		body, contentType, ok := Spec(r.PathValue("name"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, body)
	}))
	mux.HandleFunc("GET /variants", guard(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, Variants()) }))
	mux.HandleFunc("POST /delay-records", guard(func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		l.mu.Lock()
		l.recordDelay = time.Duration(ms) * time.Millisecond
		l.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /expire", guard(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.expired = true
		l.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /restore", guard(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.expired = false
		l.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /reset", guard(func(w http.ResponseWriter, r *http.Request) { l.Reset(); w.WriteHeader(http.StatusNoContent) }))
	return mux
}

// Hits returns a copy of the request log.
func (l *Lab) Hits() []Hit {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Hit(nil), l.hits...)
}

// Reset clears the request log without touching resources.
func (l *Lab) Reset() {
	l.mu.Lock()
	l.hits = nil
	l.mu.Unlock()
}

func (l *Lab) purge(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id := range l.resources {
		if strings.HasPrefix(id, prefix) {
			delete(l.resources, id)
		}
	}
}

// Resources returns the number of controlled resources that still exist.
func (l *Lab) Resources() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.resources)
}

// ExcludedPaths are routes that an approved assessment must never contact.
var ExcludedPaths = []string{PathPrefix + "logout", PathPrefix + "write", PathPrefix + "admin/delete"}

// Forbidden returns requests that violate the approved boundary: any contact
// with the alias origin, anything on the primary origin outside PathPrefix and
// the excluded logout and write routes.
func (l *Lab) Forbidden() []Hit {
	var out []Hit
	for _, hit := range l.Hits() {
		switch {
		case hit.Origin == "alias":
			out = append(out, hit)
		case hit.Origin == "primary" && !insideBoundary(hit.Path):
			out = append(out, hit)
		case hit.Origin == "primary" && excluded(hit.Path):
			out = append(out, hit)
		}
	}
	return out
}

// insideBoundary reports whether path is the approved prefix itself (with or
// without its trailing slash) or below it.
func insideBoundary(path string) bool {
	return path == strings.TrimSuffix(PathPrefix, "/") || strings.HasPrefix(path, PathPrefix)
}

func excluded(path string) bool {
	for _, p := range ExcludedPaths {
		if path == p {
			return true
		}
	}
	return false
}

// Variants returns the exact path+query of every cataloged request variant, in
// catalog order. They are distinct as raw strings, which is the identity the
// request inventory must preserve (trailing slashes, repeated and encoded
// query values).
func Variants() []string {
	out := make([]string, 0, VariantCount)
	for i := 0; i < 300; i++ {
		out = append(out, fmt.Sprintf("%sitems?id=%d", PathPrefix, i))
	}
	for i := 0; i < 100; i++ {
		out = append(out, fmt.Sprintf("%sitems/%d/", PathPrefix, i))
	}
	for i := 0; i < 100; i++ {
		out = append(out, fmt.Sprintf("%sitems/%d", PathPrefix, i))
	}
	for i := 0; i < 84; i++ {
		out = append(out, fmt.Sprintf("%ssearch?tag=a&tag=%d", PathPrefix, i))
	}
	for i := 0; i < 100; i++ {
		out = append(out, fmt.Sprintf("%sitems?name=n%%20%d", PathPrefix, i))
	}
	return out
}

func (l *Lab) record(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := Hit{Origin: origin, Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Identity: l.identity(r), UserAgent: r.UserAgent(), Login: l.loginOf(r)}
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			hit.Body = string(body)
			r.Body = io.NopCloser(strings.NewReader(hit.Body))
		}
		l.mu.Lock()
		l.hits = append(l.hits, hit)
		l.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// loginOf returns the login number that issued the request's session token.
func (l *Lab) loginOf(r *http.Request) int {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessionLogin[cookie.Value]
}

// identity names the caller, or anonymous when the lab is simulating session
// expiry.
func (l *Lab) identity(r *http.Request) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.expired {
		return "anonymous"
	}
	if cookie, err := r.Cookie(CookieName); err == nil {
		if identity, ok := l.sessions[cookie.Value]; ok {
			return identity
		}
	}
	return "anonymous"
}

func secureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (l *Lab) primaryRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathPrefix+"{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, fmt.Sprintf(`<h1>Lab home</h1>
<a href="%[1]sabout">about</a> <a href="%[1]scatalog">catalog</a> <a href="%[1]sjs">js</a>
<a href="%[1]slogin">login</a> <a href="%[1]slogout">logout</a> <a href="%[1]sredirect">redirect</a>
<a href="%[1]sitems?id=1">item 1</a> <a href="%[1]sitems?id=2">item 2</a> <a href="%[1]ssearch?q=hello">search</a>
<a href="%[2]s">outside path</a> <a href="%[3]s">alias</a> <a href="%[4]s">secondary</a> <a href="%[1]sprivate">private</a>
<form method="get" action="%[1]ssearch"><input name="q"></form>
<form method="post" action="%[1]swrite"><input name="note"><button>save</button></form>`, PathPrefix, OutsidePath, l.AliasURL+"/anything", l.SecondaryURL+"/"))
	})
	mux.HandleFunc("GET "+PathPrefix+"about", func(w http.ResponseWriter, r *http.Request) { page(w, "<h1>About</h1>") })
	mux.HandleFunc("GET "+PathPrefix+"catalog", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString("<h1>Catalog</h1>")
		for _, v := range Variants() {
			fmt.Fprintf(&b, `<a href="%s">v</a>`, html.EscapeString(v))
		}
		page(w, b.String())
	})
	item := func(w http.ResponseWriter, r *http.Request) { page(w, "<h1>Item</h1>") }
	mux.HandleFunc("GET "+PathPrefix+"items", item)
	mux.HandleFunc("GET "+PathPrefix+"items/{n}", item)
	mux.HandleFunc("GET "+PathPrefix+"items/{n}/", item)
	mux.HandleFunc("GET "+PathPrefix+"search", item)
	mux.HandleFunc("GET "+PathPrefix+"redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, PathPrefix+"about", http.StatusFound)
	})
	mux.HandleFunc("GET "+PathPrefix+"redirect-out", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, l.AliasURL+"/redirected", http.StatusFound)
	})
	mux.HandleFunc("GET "+OutsidePath, func(w http.ResponseWriter, r *http.Request) { page(w, "outside the approved path") })

	// JavaScript-only route: the dashboard path appears only in the script.
	mux.HandleFunc("GET "+PathPrefix+"js", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<div id="root"></div><script src="`+PathPrefix+`static/app.js"></script>`)
	})
	mux.HandleFunc("GET "+PathPrefix+"static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, `fetch(%q,{credentials:"same-origin"}).then(r=>r.json()).then(d=>{document.getElementById("root").textContent=d.user});
document.getElementById("root").addEventListener("click",()=>{history.pushState({},"",%q)});`, PathPrefix+"api/me", PathPrefix+"spa/dashboard")
	})
	mux.HandleFunc("GET "+PathPrefix+"spa/dashboard", func(w http.ResponseWriter, r *http.Request) { page(w, "<h1>Dashboard</h1>") })

	// Authentication and identity-specific protected routes.
	mux.HandleFunc("GET "+PathPrefix+"login", func(w http.ResponseWriter, r *http.Request) {
		page(w, fmt.Sprintf(`<form method="post" action="%slogin"><input type="hidden" name="csrf" value="%s">
<input name="username"><input name="password" type="password"><button>login</button></form>`, PathPrefix, CSRFValue))
	})
	mux.HandleFunc("POST "+PathPrefix+"login", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		expired := l.expired
		l.mu.Unlock()
		if expired {
			http.Error(w, "logins are disabled while sessions are expired", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		token, identity := "", ""
		switch {
		case r.PostForm.Get("csrf") != CSRFValue:
		case r.PostForm.Get("username") == AdminUser && secureEqual(r.PostForm.Get("password"), AdminPassword):
			token, identity = AdminToken, "admin"
		case r.PostForm.Get("username") == ViewerUser && secureEqual(r.PostForm.Get("password"), ViewerPassword):
			token, identity = ViewerToken, "viewer"
		}
		if token == "" {
			http.Error(w, "invalid login", http.StatusUnauthorized)
			return
		}
		// Every login issues a new token so a request can be traced to its login.
		l.mu.Lock()
		l.logins++
		token = fmt.Sprintf("%s-%d", token, l.logins)
		l.sessions[token] = identity
		l.sessionLogin[token] = l.logins
		l.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true})
		http.Redirect(w, r, PathPrefix+"private", http.StatusSeeOther)
	})
	mux.HandleFunc("GET "+PathPrefix+"private", func(w http.ResponseWriter, r *http.Request) {
		switch l.identity(r) {
		case "admin":
			page(w, AdminMarker)
		case "viewer":
			page(w, ViewerMarker)
		default:
			http.Error(w, "login required", http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("GET "+PathPrefix+"admin", func(w http.ResponseWriter, r *http.Request) {
		switch l.identity(r) {
		case "admin":
			page(w, "LAB_ADMIN_ONLY")
		case "viewer":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.Error(w, "login required", http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("GET "+PathPrefix+"api/me", func(w http.ResponseWriter, r *http.Request) {
		identity := l.identity(r)
		if identity == "anonymous" {
			http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]string{"user": identity})
	})

	// Excluded routes. Reaching them is a boundary violation.
	mux.HandleFunc(PathPrefix+"logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1})
		page(w, "logged out")
	})
	mux.HandleFunc("POST "+PathPrefix+"write", func(w http.ResponseWriter, r *http.Request) { page(w, "written") })
	mux.HandleFunc("POST "+PathPrefix+"admin/delete", func(w http.ResponseWriter, r *http.Request) { page(w, "deleted") })

	// API definitions: one valid OpenAPI document and two lookalikes.
	mux.HandleFunc("GET "+PathPrefix+"openapi.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"openapi": "3.0.3", "info": map[string]string{"title": "Lab API", "version": "1"},
			"paths": map[string]any{
				PathPrefix + "api/records": map[string]any{
					"get":  map[string]any{"operationId": "listRecords", "responses": map[string]any{"200": map[string]string{"description": "ok"}}},
					"post": map[string]any{"operationId": "createRecord", "requestBody": map[string]any{"content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{"type": "object"}}}}, "responses": map[string]any{"201": map[string]string{"description": "created"}}},
				},
				PathPrefix + "api/records/{id}": map[string]any{
					"get":    map[string]any{"operationId": "getRecord", "parameters": []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}}, "responses": map[string]any{"200": map[string]string{"description": "ok"}}},
					"delete": map[string]any{"operationId": "deleteRecord", "parameters": []any{map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]string{"type": "string"}}}, "responses": map[string]any{"204": map[string]string{"description": "deleted"}}},
				},
			},
		})
	})
	mux.HandleFunc("GET "+PathPrefix+"openapi-lookalike.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"openapi": "3.0.3", "info": "not an object", "paths": []string{"not", "a", "map"}})
	})
	mux.HandleFunc("GET "+PathPrefix+"api-docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>"openapi": "3.0.0" appears in prose, not as a schema</body></html>`)
	})

	// Controlled resource used by the approved POST campaign and its cleanup.
	mux.HandleFunc("GET "+PathPrefix+"api/records", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		ids := make([]string, 0, len(l.resources))
		for id := range l.resources {
			ids = append(ids, id)
		}
		l.mu.Unlock()
		writeJSON(w, map[string]any{"records": ids})
	})
	mux.HandleFunc("POST "+PathPrefix+"api/records", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		delay := l.recordDelay
		l.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		_ = r.ParseForm()
		l.mu.Lock()
		l.nextID++
		id := fmt.Sprintf("rec-%d", l.nextID)
		l.resources[id] = r.PostForm.Get("name")
		l.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]string{"id": id})
	})
	mux.HandleFunc("GET "+PathPrefix+"api/records/{id}", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		_, ok := l.resources[r.PathValue("id")]
		l.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]string{"id": r.PathValue("id")})
	})
	mux.HandleFunc("DELETE "+PathPrefix+"api/records/{id}", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		_, ok := l.resources[r.PathValue("id")]
		delete(l.resources, r.PathValue("id"))
		l.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Literal, idempotent cleanup routes: an approved campaign may create many
	// records and the cleanup path cannot carry a placeholder.
	mux.HandleFunc("DELETE "+PathPrefix+"api/records/fixture", func(w http.ResponseWriter, r *http.Request) {
		l.purge("rec-")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST "+PathPrefix+"api/notes", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		l.mu.Lock()
		l.nextID++
		id := fmt.Sprintf("note-%d", l.nextID)
		l.resources[id] = r.PostForm.Get("text")
		l.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]string{"id": id})
	})
	mux.HandleFunc("DELETE "+PathPrefix+"api/notes/fixture", func(w http.ResponseWriter, r *http.Request) {
		l.purge("note-")
		w.WriteHeader(http.StatusNoContent)
	})

	// GraphQL: introspection enabled over GET and POST, and a sibling endpoint that
	// answers 200 with introspection disabled.
	mux.HandleFunc(PathPrefix+"graphql", func(w http.ResponseWriter, r *http.Request) { graphql(w, r, true) })
	mux.HandleFunc(PathPrefix+"graphql-noint", func(w http.ResponseWriter, r *http.Request) { graphql(w, r, false) })
	return mux
}

func (l *Lab) secondaryRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, `<h1>Secondary service</h1><a href="/status">status</a>`)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"status": "ok"}) })
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) { graphql(w, r, false) })
	return mux
}

func graphql(w http.ResponseWriter, r *http.Request, introspection bool) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if r.Method == http.MethodGet {
		req.Query = r.URL.Query().Get("query")
		if raw := r.URL.Query().Get("variables"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &req.Variables)
		}
	} else if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, `{"errors":[{"message":"invalid request"}]}`, http.StatusBadRequest)
		return
	}
	switch {
	case strings.Contains(req.Query, "__schema"):
		if !introspection {
			writeJSON(w, map[string]any{"errors": []map[string]string{{"message": "introspection is disabled"}}})
			return
		}
		idArg := map[string]any{"name": "id", "type": map[string]any{"kind": "NON_NULL", "ofType": map[string]string{"kind": "SCALAR", "name": "ID"}}}
		writeJSON(w, map[string]any{"data": map[string]any{"__schema": map[string]any{
			"queryType": map[string]any{"name": "Query", "fields": []any{
				map[string]any{"name": "record", "args": []any{idArg}, "type": map[string]string{"kind": "SCALAR", "name": "String"}},
			}},
			"mutationType": map[string]any{"name": "Mutation", "fields": []any{
				map[string]any{"name": "deleteRecord", "args": []any{idArg}, "type": map[string]string{"kind": "SCALAR", "name": "Boolean"}},
			}},
		}}})
	case strings.HasPrefix(strings.TrimSpace(req.Query), "mutation"):
		writeJSON(w, map[string]any{"errors": []map[string]string{{"message": "mutations are not available in the lab"}}})
	default:
		writeJSON(w, map[string]any{"data": map[string]any{"record": fmt.Sprint(req.Variables["id"])}})
	}
}

func page(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><html><head><title>Lab</title></head><body>%s</body></html>", body)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

// MustParse parses a lab URL for tests.
func MustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

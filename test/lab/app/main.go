package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// This application is a deliberately small scanner fixture. The vulnerable
// variant exposes only synthetic data and must remain bound to local test ports.
type labApp struct {
	vulnerable bool
	name       string
}

func main() {
	app := labApp{vulnerable: os.Getenv("LAB_VARIANT") == "vulnerable", name: os.Getenv("LAB_NAME")}
	if app.name == "" {
		app.name = "app-a"
	}
	log.Fatal(http.ListenAndServe(":8080", app.routes()))
}

func (app labApp) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("GET /{$}", app.index)
	mux.HandleFunc("GET /search", app.search)
	mux.HandleFunc("GET /items", app.items)
	mux.HandleFunc("GET /file", app.file)
	mux.HandleFunc("GET /.env", app.exposedFile)
	mux.HandleFunc("GET /js", app.js)
	mux.HandleFunc("GET /js/profile", app.jsProfile)
	mux.HandleFunc("GET /login", app.loginForm)
	mux.HandleFunc("POST /login", app.login)
	mux.HandleFunc("GET /private", app.private)
	mux.HandleFunc("GET /redirect", app.redirect)
	mux.HandleFunc("GET /openapi.json", app.openAPI)
	mux.HandleFunc("GET /api/records", app.records)
	mux.HandleFunc("GET /api/private", app.privateAPI)
	return mux
}

func (app labApp) index(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, `<!doctype html><title>%s</title><a href="/search?q=hello">Search</a><a href="/items?id=1">Items</a><a href="/file?name=public.txt">File</a><a href="/js">JavaScript routes</a><a href="/login">Login</a><a href="/redirect">Redirect</a>`, html.EscapeString(app.name))
}

func (app labApp) search(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("q")
	if !app.vulnerable {
		value = html.EscapeString(value)
	}
	fmt.Fprintf(w, "<!doctype html><title>Search</title><p>Result: %s</p>", value)
}

func (app labApp) items(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if !app.vulnerable {
		if _, err := strconv.Atoi(id); err != nil {
			http.Error(w, "invalid item ID", http.StatusBadRequest)
			return
		}
	}
	if app.vulnerable && strings.Contains(strings.ToLower(id), "or 1=1") {
		fmt.Fprint(w, "item 1, item 2")
		return
	}
	if strings.ContainsAny(id, "'\";") {
		if app.vulnerable {
			http.Error(w, "SQL syntax error near WHERE id="+id, http.StatusInternalServerError)
		}
		return
	}
	fmt.Fprintf(w, "item %s", html.EscapeString(id))
}

func (app labApp) file(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if strings.Contains(name, "..") {
		if app.vulnerable {
			fmt.Fprint(w, "LAB_PRIVATE_FILE_SENTINEL")
		} else {
			http.Error(w, "invalid file name", http.StatusBadRequest)
		}
		return
	}
	if name != "public.txt" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, "public test content")
}

func (app labApp) exposedFile(w http.ResponseWriter, r *http.Request) {
	if !app.vulnerable {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, "LAB_FAKE_KEY=fixture-only-do-not-use")
}

func (app labApp) js(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `<!doctype html><title>JavaScript routes</title><main id="view"></main><script>fetch('/js/profile').then(r=>r.text()).then(t=>{document.getElementById('view').innerHTML=t})</script>`)
}

func (app labApp) jsProfile(w http.ResponseWriter, _ *http.Request) {
	sink := "textContent"
	if app.vulnerable {
		sink = "innerHTML"
	}
	fmt.Fprintf(w, `<a href="/private">Private area</a><div id="profile"></div><script>document.getElementById('profile').%s=decodeURIComponent(location.hash.slice(1))</script>`, sink)
}

func (app labApp) loginForm(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, `<!doctype html><form action="/login" method="post"><input type="hidden" name="csrf" value="lab-csrf-token"><input name="username"><input name="password" type="password"><button>Log in</button></form>`)
}

func (app labApp) login(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("csrf") != "lab-csrf-token" || r.PostFormValue("username") != "lab-user" || r.PostFormValue("password") != "lab-password" {
		http.Error(w, "invalid login", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "lab_session", Value: "valid", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/private", http.StatusSeeOther)
}

func authenticated(r *http.Request) bool {
	cookie, err := r.Cookie("lab_session")
	return err == nil && cookie.Value == "valid"
}

func (app labApp) private(w http.ResponseWriter, r *http.Request) {
	if !authenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	fmt.Fprintf(w, `<!doctype html><title>Account</title><p>LAB_AUTHENTICATED_MARKER</p><a href="/api/private">Private API</a><a href="/search?q=private">Private search</a>`)
}

func (app labApp) redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/search?q=redirected", http.StatusFound)
}

func (app labApp) openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "Xalgorix lab", "version": "1.0.0"}, "paths": map[string]any{"/api/records": map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "records"}}}}, "/api/private": map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "private records"}}}}}})
}

func (app labApp) records(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"records":["public"]}`)
}

func (app labApp) privateAPI(w http.ResponseWriter, r *http.Request) {
	if !authenticated(r) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"records":["private"]}`)
}

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestVulnerableAndFixedLabCounterparts(t *testing.T) {
	for _, test := range []struct {
		path       string
		vulnerable string
		fixed      string
	}{
		{path: "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", vulnerable: "<script>alert(1)</script>", fixed: "&lt;script&gt;"},
		{path: "/items?id=1%27", vulnerable: "SQL syntax error", fixed: "invalid item ID"},
		{path: "/items?id=1%20OR%201%3D1", vulnerable: "item 1, item 2", fixed: "invalid item ID"},
		{path: "/file?name=..%2Fprivate.txt", vulnerable: "LAB_PRIVATE_FILE_SENTINEL", fixed: "invalid file name"},
		{path: "/.env", vulnerable: "LAB_FAKE_KEY", fixed: "404 page not found"},
		{path: "/js/profile", vulnerable: ".innerHTML=", fixed: ".textContent="},
	} {
		for _, variant := range []struct {
			name       string
			vulnerable bool
			want       string
		}{{"vulnerable", true, test.vulnerable}, {"fixed", false, test.fixed}} {
			t.Run(variant.name+test.path, func(t *testing.T) {
				response := httptest.NewRecorder()
				(labApp{vulnerable: variant.vulnerable, name: "app-a"}).routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
				if !strings.Contains(response.Body.String(), variant.want) {
					t.Fatalf("body %q does not contain %q", response.Body.String(), variant.want)
				}
			})
		}
	}
}

func TestLabLoginAndAPIRequireCookie(t *testing.T) {
	server := httptest.NewServer((labApp{vulnerable: true, name: "app-a"}).routes())
	defer server.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(server.URL + "/api/private")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous API status = %d", response.StatusCode)
	}
	response, err = client.PostForm(server.URL+"/login", url.Values{"username": {"lab-user"}, "password": {"lab-password"}, "csrf": {"lab-csrf-token"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || len(response.Cookies()) != 1 {
		t.Fatalf("login status/cookies = %d/%v", response.StatusCode, response.Cookies())
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/private", nil)
	request.AddCookie(response.Cookies()[0])
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(content), "private") {
		t.Fatalf("authenticated API status/body = %d/%s", response.StatusCode, content)
	}
}

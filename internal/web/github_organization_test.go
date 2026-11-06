package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type githubTestTransport func(*http.Request) (*http.Response, error)

func (f githubTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGitHubOrganizationInput(t *testing.T) {
	for _, input := range []string{"example-org", "https://github.com/example-org/"} {
		org, err := githubOrganization(input)
		if err != nil || org != "example-org" {
			t.Fatalf("%q: %q %v", input, org, err)
		}
	}
	for _, input := range []string{"https://evil.test/org", "https://github.com/org/repo", "https://token@github.com/org", "org/repo", "https://github.com/org?q=x", "http://github.com/org", ""} {
		if _, err := githubOrganization(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestGitHubDiscoveryPaginationAndNoPartialResults(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		calls := 0
		client := &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.URL.Host != "api.github.com" || r.Header.Get("Authorization") != "Bearer secret" {
				t.Fatal("incorrect API request")
			}
			if r.URL.Query().Get("page") != fmt.Sprint(calls) {
				t.Fatal("incorrect page")
			}
			status := 200
			batch := []githubRepository{}
			if calls == 1 {
				for i := 1; i <= 100; i++ {
					batch = append(batch, githubRepository{ID: int64(i), FullName: fmt.Sprintf("org/repo%d", i), CloneURL: fmt.Sprintf("https://github.com/org/repo%d.git", i), DefaultBranch: "main", Private: i%2 == 0, Archived: i%3 == 0, Fork: i%5 == 0})
				}
			} else if failSecond {
				status = 403
			}
			data, _ := json.Marshal(batch)
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
		})}
		repos, err := discoverGitHubRepositories(t.Context(), client, "org", "secret")
		if calls != 2 {
			t.Fatalf("calls=%d", calls)
		}
		if failSecond {
			if err == nil || repos != nil {
				t.Fatal("returned incomplete inventory")
			}
		} else if err != nil || len(repos) != 100 {
			t.Fatalf("repos=%d err=%v", len(repos), err)
		}
	}
}

func TestGitHubDiscoveryRejectsForeignCloneURL(t *testing.T) {
	client := &http.Client{Transport: githubTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":1,"clone_url":"https://evil.test/org/repo.git"}]`))}, nil
	})}
	if repos, err := discoverGitHubRepositories(t.Context(), client, "org", ""); err == nil || repos != nil {
		t.Fatal("accepted foreign repository URL")
	}
}

func TestGitHubDiscoveryRequestValidation(t *testing.T) {
	server := newTestServer(t, nil)
	for _, test := range []struct {
		method, body string
		status       int
	}{{"GET", "", 405}, {"POST", `{"organization":"https://evil.test/org"}`, 400}, {"POST", `{`, 400}} {
		response := httptest.NewRecorder()
		server.handleGitHubOrganization(response, httptest.NewRequest(test.method, "/api/github/organization/repositories", strings.NewReader(test.body)))
		if response.Code != test.status {
			t.Fatalf("status=%d want=%d", response.Code, test.status)
		}
	}
}

func TestGitHubDiscoveryBindsEncryptedTokenToRepositoryTargets(t *testing.T) {
	server := newTestServer(t, nil)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{0x31}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CREDENTIAL_KEY_FILE", key)
	vault, err := server.credentialVault()
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.Create(credentials.Record{Name: "org", Kind: assessment.AccessRepositoryCreds, TargetIDs: []string{"github-org:org"}, Values: map[string]string{"token": "secret-token"}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.githubClient = &http.Client{Transport: githubTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			t.Fatal("token missing")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":42,"full_name":"org/private","clone_url":"https://github.com/org/private.git","default_branch":"main","private":true}]`))}, nil
	})}
	for _, org := range []string{"other", "org"} {
		response := httptest.NewRecorder()
		body := fmt.Sprintf(`{"organization":%q,"credential_id":%q}`, org, meta.ID)
		server.handleGitHubOrganization(response, httptest.NewRequest("POST", "/api/github/organization/repositories", strings.NewReader(body)))
		want := 200
		if org == "other" {
			want = 403
		}
		if response.Code != want || strings.Contains(response.Body.String(), "secret-token") {
			t.Fatalf("response=%d %s", response.Code, response.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("unbound credential made API request: calls=%d", calls)
	}
	record, err := vault.Get(meta.ID, "artifact-github-42")
	if err != nil || record.Values["token"] != "secret-token" {
		t.Fatalf("binding failed: %v", err)
	}
}

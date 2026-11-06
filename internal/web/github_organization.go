package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type githubRepository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
}

func githubOrganization(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", fmt.Errorf("use a GitHub.com organization name or HTTPS organization URL")
		}
		raw = strings.Trim(u.Path, "/")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$`).MatchString(raw) {
		return "", fmt.Errorf("invalid GitHub organization name")
	}
	return raw, nil
}

// A failed page never returns a partial inventory. The client follows only
// locally constructed GitHub API URLs, and never forwards tokens on redirects.
func discoverGitHubRepositories(ctx context.Context, client *http.Client, org, token string) ([]githubRepository, error) {
	repos := []githubRepository{}
	seen := map[int64]bool{}
	for page := 1; ; page++ {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.github.com/orgs/%s/repos?type=all&per_page=100&page=%d", url.PathEscape(org), page), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GitHub discovery unavailable; retry discovery")
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("GitHub discovery returned HTTP %d; check organization, token access, or rate limits", resp.StatusCode)
		}
		var batch []githubRepository
		err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 8<<20)).Decode(&batch)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("invalid GitHub repository response; retry discovery")
		}
		for _, repo := range batch {
			u, err := url.Parse(repo.CloneURL)
			if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.EqualFold(strings.Split(strings.Trim(u.Path, "/"), "/")[0], org) {
				return nil, fmt.Errorf("invalid repository URL in GitHub response")
			}
			if !seen[repo.ID] {
				repos = append(repos, repo)
				seen[repo.ID] = true
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return repos, nil
}

func (s *Server) handleGitHubOrganization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	var input struct {
		Organization string `json:"organization"`
		CredentialID string `json:"credential_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input) != nil {
		http.Error(w, "invalid discovery request", 400)
		return
	}
	org, err := githubOrganization(input.Organization)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	token := ""
	if input.CredentialID != "" {
		vault, err := s.openCredentialVault()
		if err != nil {
			http.Error(w, "credential storage unavailable", 503)
			return
		}
		record, err := vault.Get(input.CredentialID, "github-org:"+strings.ToLower(org))
		if err != nil || record.Kind != assessment.AccessRepositoryCreds {
			http.Error(w, "repository credential is not accessible for this organization", 403)
			return
		}
		token = record.Values["token"]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if s.githubClient != nil {
		client = s.githubClient
	}
	repos, err := discoverGitHubRepositories(ctx, client, org, token)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	if input.CredentialID != "" {
		vault, err := s.openCredentialVault()
		if err != nil {
			http.Error(w, "credential storage unavailable", 503)
			return
		}
		record, err := vault.Get(input.CredentialID, "github-org:"+strings.ToLower(org))
		if err != nil {
			http.Error(w, "credential unavailable", 403)
			return
		}
		record.TargetIDs = []string{"github-org:" + strings.ToLower(org)}
		for _, repo := range repos {
			record.TargetIDs = append(record.TargetIDs, fmt.Sprintf("artifact-github-%d", repo.ID))
		}
		if _, err := vault.Replace(record.ID, record); err != nil {
			http.Error(w, "could not bind repository credentials", 500)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"repositories": repos})
}

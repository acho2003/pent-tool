package llm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// TestBuildCatalogEndpoint_CodexResponses is the regression guard for the
// bug where the per-scan resolver (internal/web/scan_resolve.go) used a
// divergent endpoint builder that lacked the "openai_responses" case: it
// sent Codex traffic to <base>/v1/chat/completions (legacy chat-completions
// → Cloudflare 403) and dropped the required ChatGPT headers. Both the
// composite resolver and the per-scan resolver now call BuildCatalogEndpoint,
// so this test pins the correct URL + header behavior in one place.
func TestBuildCatalogEndpoint_CodexResponses(t *testing.T) {
	entry := providers.Entry{
		ID:          "codex",
		BaseURL:     "https://chatgpt.com/backend-api/codex",
		HeaderStyle: "openai_responses",
		Models:      []string{"gpt-5.5", "gpt-5.5-codex"},
	}
	prof := auth.Profile{
		Provider:    "codex",
		ProfileID:   "default",
		Type:        auth.OAuth,
		AccessToken: "tok_codex",
		AccountID:   "acct_codex_77",
	}

	ep, err := BuildCatalogEndpoint(entry, prof, "")
	if err != nil {
		t.Fatalf("BuildCatalogEndpoint: %v", err)
	}

	// Must hit the Responses API path, NOT /v1/chat/completions.
	if ep.URL != "https://chatgpt.com/backend-api/codex/responses" {
		t.Errorf("URL = %q, want .../codex/responses", ep.URL)
	}
	if ep.HeaderStyle != "openai_responses" {
		t.Errorf("HeaderStyle = %q, want openai_responses", ep.HeaderStyle)
	}
	if ep.Auth != AuthOAuthBearer || ep.AccessToken != "tok_codex" {
		t.Errorf("auth = %v token = %q, want OAuth bearer tok_codex", ep.Auth, ep.AccessToken)
	}
	if ep.Model != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5 (first catalog model)", ep.Model)
	}

	// VendorOverride must attach the three Codex/ChatGPT headers.
	if ep.VendorOverride == nil {
		t.Fatal("VendorOverride is nil; codex headers would be dropped")
	}
	req := httptest.NewRequest(http.MethodPost, ep.URL, nil)
	ep.VendorOverride(req)
	if got := req.Header.Get("chatgpt-account-id"); got != "acct_codex_77" {
		t.Errorf("chatgpt-account-id = %q, want acct_codex_77", got)
	}
	if got := req.Header.Get("OpenAI-Beta"); got != "responses=experimental" {
		t.Errorf("OpenAI-Beta = %q, want responses=experimental", got)
	}
	if got := req.Header.Get("originator"); got != "codex_cli_rs" {
		t.Errorf("originator = %q, want codex_cli_rs", got)
	}
}

// TestBuildCatalogEndpoint_PreferModel verifies an explicit preferModel
// overrides the catalog's default first model.
func TestBuildCatalogEndpoint_PreferModel(t *testing.T) {
	entry := providers.Entry{
		ID:          "codex",
		BaseURL:     "https://chatgpt.com/backend-api/codex",
		HeaderStyle: "openai_responses",
		Models:      []string{"gpt-5.5"},
	}
	prof := auth.Profile{Provider: "codex", ProfileID: "default", Type: auth.OAuth, AccessToken: "t"}
	ep, err := BuildCatalogEndpoint(entry, prof, "gpt-5.5-codex")
	if err != nil {
		t.Fatalf("BuildCatalogEndpoint: %v", err)
	}
	if ep.Model != "gpt-5.5-codex" {
		t.Errorf("model = %q, want gpt-5.5-codex (preferModel wins)", ep.Model)
	}
}

// TestBuildCatalogEndpoint_OpenAIAndUnknown covers the openai chat path and
// the unsupported-header-style error.
func TestBuildCatalogEndpoint_OpenAIAndUnknown(t *testing.T) {
	openai := providers.Entry{
		ID:          "openai",
		BaseURL:     "https://api.openai.com/v1",
		HeaderStyle: "openai",
		Models:      []string{"gpt-5.5"},
	}
	keyProf := auth.Profile{Provider: "openai", ProfileID: "default", Type: auth.APIKey, APIKey: "sk-x"}
	ep, err := BuildCatalogEndpoint(openai, keyProf, "")
	if err != nil {
		t.Fatalf("openai BuildCatalogEndpoint: %v", err)
	}
	if ep.URL != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("openai URL = %q", ep.URL)
	}
	if ep.Auth != AuthAPIKey || ep.APIKey != "sk-x" {
		t.Errorf("openai auth = %v key = %q, want APIKey sk-x", ep.Auth, ep.APIKey)
	}
	if ep.VendorOverride != nil {
		t.Error("openai endpoint should not set a codex VendorOverride")
	}

	bad := providers.Entry{ID: "weird", BaseURL: "https://x", HeaderStyle: "made-up"}
	if _, err := BuildCatalogEndpoint(bad, keyProf, ""); err == nil {
		t.Error("expected error for unsupported header style, got nil")
	}
}

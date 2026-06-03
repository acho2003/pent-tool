package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// makeJWT builds an unsigned-but-structurally-valid JWT (header.payload.sig)
// whose payload is the supplied claims. Signature is a dummy segment — the
// extractor never verifies it.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".sig"
}

func codexEntry() providers.Entry {
	return providers.Entry{
		ID:                    "codex",
		DisplayName:           "Codex (ChatGPT Subscription)",
		BaseURL:               "https://chatgpt.com/backend-api/codex",
		HeaderStyle:           "openai_responses",
		Flow:                  "pkce",
		ClientID:              "app_EMoamEEZ73f0CkXaXp7hrann",
		AuthorizationEndpoint: "https://auth.openai.com/oauth/authorize",
		TokenEndpoint:         "https://auth.openai.com/oauth/token",
		Scopes:                []string{"openid", "profile", "email", "offline_access"},
	}
}

// TestExtractChatGPTAccountID pulls the chatgpt_account_id from the namespaced
// auth claim and returns "" for tokens that lack it.
func TestExtractChatGPTAccountID(t *testing.T) {
	tok := makeJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct_9f3",
		},
		"sub": "user_1",
	})
	if got := extractChatGPTAccountID(tok); got != "acct_9f3" {
		t.Errorf("account id = %q, want acct_9f3", got)
	}

	// Missing claim → empty.
	noClaim := makeJWT(t, map[string]any{"sub": "user_1"})
	if got := extractChatGPTAccountID(noClaim); got != "" {
		t.Errorf("account id = %q, want empty for token without claim", got)
	}

	// Malformed token → empty, no panic.
	if got := extractChatGPTAccountID("not-a-jwt"); got != "" {
		t.Errorf("account id = %q, want empty for malformed token", got)
	}
}

// TestCodexAuthURL_CarriesCodexParams asserts the authorization URL built for
// a Codex entry includes the three Codex-specific params and S256 PKCE.
func TestCodexAuthURL_CarriesCodexParams(t *testing.T) {
	e := codexEntry()
	raw := pkceBuildAuthURL(e, codexRedirectURI, "state123", "challengeABC")
	vals := authURLValues(t, raw)

	checks := map[string]string{
		"codex_cli_simplified_flow":  "true",
		"id_token_add_organizations": "true",
		"originator":                 "codex_cli_rs",
		"code_challenge_method":      "S256",
		"redirect_uri":               codexRedirectURI,
		"client_id":                  e.ClientID,
	}
	for k, want := range checks {
		if got := vals.Get(k); got != want {
			t.Errorf("auth URL param %q = %q, want %q", k, got, want)
		}
	}
}

// TestNonCodexAuthURL_OmitsCodexParams ensures a vanilla PKCE provider's
// authorize URL is unchanged (no Codex params leak in).
func TestNonCodexAuthURL_OmitsCodexParams(t *testing.T) {
	e := providers.Entry{
		ID:                    "google",
		HeaderStyle:           "gemini",
		Flow:                  "pkce",
		ClientID:              "g-client",
		AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
		Scopes:                []string{"openid"},
	}
	vals := authURLValues(t, pkceBuildAuthURL(e, "http://127.0.0.1:5/cb", "s", "c"))
	for _, k := range []string{"codex_cli_simplified_flow", "id_token_add_organizations", "originator"} {
		if vals.Has(k) {
			t.Errorf("non-Codex auth URL unexpectedly carries %q", k)
		}
	}
}

// TestCodexPasteFlow_UsesFixedRedirect asserts the paste-mode Start for a
// Codex entry advertises the registered loopback redirect (not the OOB urn).
func TestCodexPasteFlow_UsesFixedRedirect(t *testing.T) {
	store := newCodexTestStore(t)
	d := newPKCEDriver(store, nil)

	res, err := d.Start(context.Background(), codexEntry(), StartOptions{PreferPaste: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Mode != "paste" {
		t.Fatalf("mode = %q, want paste", res.Mode)
	}
	vals := authURLValues(t, res.AuthURL)
	if got := vals.Get("redirect_uri"); got != codexRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", got, codexRedirectURI)
	}
}

// TestCodexExchange_PopulatesAccountID drives the paste-fallback Complete
// path with a token response whose access_token JWT carries the account id,
// and asserts the persisted profile records it.
func TestCodexExchange_PopulatesAccountID(t *testing.T) {
	f := newPKCETestFixture(t)
	// Repoint the fixture's entry/catalog at a Codex-style entry that still
	// uses the stub token server.
	f.entry.HeaderStyle = "openai_responses"
	access := makeJWT(t, map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct_codex_42"},
	})
	f.setExpectedCode("codex-code")
	f.setNextOK(`{"access_token":"` + access + `","refresh_token":"rt","token_type":"bearer","expires_in":3600,"scope":"openid"}`)

	res, err := f.driver.Start(context.Background(), f.entry, StartOptions{PreferPaste: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	prof, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{
		FlowID:            res.FlowID,
		AuthorizationCode: "codex-code",
		State:             authURLValues(t, res.AuthURL).Get("state"),
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if prof.AccountID != "acct_codex_42" {
		t.Errorf("profile AccountID = %q, want acct_codex_42", prof.AccountID)
	}
}

func newCodexTestStore(t *testing.T) *Store {
	t.Helper()
	cat := &pkceStubCatalog{id: "codex", entry: codexEntry()}
	store, err := NewStore(filepath.Join(t.TempDir(), "auth-profiles.json"), cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// guard against accidental import removal.
var _ = strings.TrimSpace

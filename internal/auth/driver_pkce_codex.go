package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// Codex / ChatGPT-subscription OAuth specifics.
//
// The OpenAI Codex OAuth flow (the same one the official `codex` CLI uses)
// differs from a vanilla RFC 7636 PKCE flow in three ways that the generic
// pkceDriver cannot infer from the catalog entry alone:
//
//  1. The OAuth client is registered for the FIXED loopback redirect
//     http://localhost:1455/auth/callback — an ephemeral port is rejected
//     by the authorization server.
//  2. The authorization request must carry three extra query params
//     (codex_cli_simplified_flow, id_token_add_organizations, originator)
//     or the issued token is not usable against the ChatGPT backend.
//  3. The ChatGPT backend requires a `chatgpt-account-id` request header
//     whose value lives in the access token's JWT claim
//     `https://api.openai.com/auth` → `chatgpt_account_id`.
//
// These are gated to entries whose HeaderStyle routes through the
// Responses API (headerStyleResponsesCatalog), so every other PKCE
// provider (Google, xAI, …) is unaffected.

const (
	// headerStyleResponsesCatalog mirrors the llm package's
	// headerStyleResponses value. Duplicated here (rather than imported)
	// because internal/auth must not depend on internal/llm — the auth
	// package is a leaf consumed by llm, not the other way around.
	headerStyleResponsesCatalog = "openai_responses"

	// codexFixedRedirectHost is the loopback host:port the Codex OAuth
	// listener binds. We bind 127.0.0.1 (explicit loopback) but advertise
	// the redirect_uri with the "localhost" hostname below — the browser
	// resolves localhost to 127.0.0.1, so the callback still lands here.
	codexFixedRedirectHost = "127.0.0.1:1455"

	// codexCallbackPath is the fixed callback path the Codex client
	// expects (distinct from the generic pkceCallbackPath).
	codexCallbackPath = "/auth/callback"

	// codexRedirectURI is the EXACT redirect_uri the OpenAI authorization
	// server validates against. It MUST match the value registered for the
	// official Codex OAuth client byte-for-byte — that registration uses the
	// "localhost" hostname (not 127.0.0.1). Advertising 127.0.0.1 here makes
	// the authorize endpoint reject the request with
	// authorize_hydra_invalid_request.
	codexRedirectURI = "http://localhost:1455/auth/callback"

	// jwtAuthClaim is the namespaced claim object in the Codex access
	// token that carries chatgpt_account_id.
	jwtAuthClaim = "https://api.openai.com/auth"
)

// isCodexEntry reports whether a catalog entry uses the Codex / ChatGPT
// Responses flow and therefore needs the Codex-specific OAuth handling.
func isCodexEntry(e providers.Entry) bool {
	return strings.EqualFold(strings.TrimSpace(e.HeaderStyle), headerStyleResponsesCatalog)
}

// codexAuthParams returns the extra authorization-request query params the
// Codex flow requires. Empty for non-Codex entries.
func codexAuthParams(e providers.Entry) map[string]string {
	if !isCodexEntry(e) {
		return nil
	}
	return map[string]string{
		"codex_cli_simplified_flow":  "true",
		"id_token_add_organizations": "true",
		"originator":                 "codex_cli_rs",
	}
}

// extractChatGPTAccountID decodes a JWT access token (without verifying the
// signature — the token came straight from the token endpoint over TLS) and
// returns the chatgpt_account_id claim, or "" when absent/unparseable. The
// claim lives under the namespaced object jwtAuthClaim.
func extractChatGPTAccountID(accessToken string) string {
	claims := decodeJWTClaims(accessToken)
	if claims == nil {
		return ""
	}
	authObj, ok := claims[jwtAuthClaim].(map[string]any)
	if !ok {
		return ""
	}
	if id, ok := authObj["chatgpt_account_id"].(string); ok {
		return strings.TrimSpace(id)
	}
	return ""
}

// decodeJWTClaims base64url-decodes the payload segment of a JWT and
// unmarshals it into a generic claims map. Returns nil on any structural
// problem. Signature verification is intentionally omitted: the token is
// consumed locally as an opaque bearer credential, and it arrived directly
// from the provider's TLS-protected token endpoint.
func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers pad; fall back to standard base64url with padding.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}

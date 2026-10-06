package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

func bodyDigest(body string) string {
	if body == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
func requestVariantEndpoint(scope, raw, method, contentType, body string, authenticated bool) (AttackSurfaceEndpoint, bool) {
	params := append(endpointParameters(raw), bodyParameters(body, contentType)...)
	endpoint, ok := normalizeAttackSurfaceEndpoint(raw, method, "browser", "", 0, "", params, false, authenticated)
	if !ok {
		return endpoint, false
	}
	endpoint.BodyDigest = bodyDigest(body)
	if endpoint.BodyDigest != "" {
		endpoint.ID = inventoryID(endpoint.ID, endpoint.BodyDigest)
	}
	endpoint.RequestContentType = contentType
	if contentType != "" {
		endpoint.ID = inventoryID(endpoint.ID, contentType)
	}
	if authenticated {
		endpoint.AuthContextID = inventoryID(scope, "target-bound")
		endpoint.ID = inventoryID(endpoint.ID, endpoint.AuthContextID)
	}
	return endpoint, true
}

// sealInventoryRequests preserves sensitive supplied URLs before public snapshots
// redact them. Body-bearing variants require their original capture, never a
// synthesized replay from a digest.
func sealInventoryRequests(surface *AttackSurface, store *credentials.ReplayStore, scope string) {
	if surface == nil {
		return
	}
	for i := range surface.Endpoints {
		ep := &surface.Endpoints[i]
		if ep.ReplayRef != "" || SafeTelemetryURL(ep.URL) == ep.URL {
			continue
		}
		if ep.BodyDigest != "" {
			ep.State, ep.StateReason = EndpointStateUnmaterialized, "sensitive request URL requires original encrypted replay"
			continue
		}
		ref, err := store.Put(scope, ep.AuthContextID, credentials.ReplayRequest{EndpointID: ep.ID, URL: ep.URL, Method: ep.Method, ContentType: ep.RequestContentType})
		if err != nil {
			ep.State, ep.StateReason = EndpointStateUnmaterialized, "sensitive request URL requires encrypted replay"
			continue
		}
		ep.ReplayRef = ref
	}
}

func hydrateRequestReplay(surface *AttackSurface, store *credentials.ReplayStore, scope string) {
	if surface == nil {
		return
	}
	for i := range surface.Endpoints {
		endpoint := &surface.Endpoints[i]
		if endpoint.ReplayRef == "" {
			continue
		}
		request, err := store.Get(scope, endpoint.AuthContextID, endpoint.ReplayRef)
		if err == nil && (request.EndpointID != endpoint.ID || request.Method != endpoint.Method || request.ContentType != endpoint.RequestContentType || bodyDigest(request.Body) != endpoint.BodyDigest) {
			err = fmt.Errorf("replay request does not match inventory")
		}
		if err != nil {
			endpoint.State, endpoint.StateReason = EndpointStateUnmaterialized, "encrypted request replay unavailable or incompatible"
			continue
		}
		if endpoint.StateReason == "encrypted request replay unavailable or incompatible" {
			endpoint.State, endpoint.StateReason = EndpointStateInScope, ""
		}
		endpoint.URL = request.URL
		endpoint.ReplayBody, endpoint.ReplayHeaders = request.Body, request.Headers
	}
}

// replaySecrets augments the existing scanner-output redactor with credentials
// derived by the browser, which may differ from configured authentication.
func replaySecrets(inputs []ScannerRequestInput) []string {
	var secrets []string
	sensitive := func(key string) bool {
		lower := strings.ToLower(key)
		for _, marker := range []string{"token", "secret", "password", "passwd", "session", "cookie", "authorization", "credential", "signature", "csrf", "api_key", "apikey"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
		return lower == "key" || lower == "sig" || lower == "jwt" || lower == "code"
	}
	var walk func(any, bool)
	walk = func(value any, private bool) {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				walk(child, private || sensitive(k))
			}
		case []any:
			for _, child := range v {
				walk(child, private)
			}
		case string:
			if private && v != "" {
				secrets = append(secrets, v)
			}
		}
	}
	for _, input := range inputs {
		for name, value := range input.Headers {
			if sensitive(name) && value != "" {
				secrets = append(secrets, value)
				if strings.EqualFold(name, "Cookie") {
					for _, part := range strings.Split(value, ";") {
						if _, secret, ok := strings.Cut(strings.TrimSpace(part), "="); ok && secret != "" {
							secrets = append(secrets, secret)
						}
					}
				}
				if strings.HasPrefix(strings.ToLower(value), "bearer ") {
					secrets = append(secrets, strings.TrimSpace(value[7:]))
				}
			}
		}
		if u, err := url.Parse(input.URL); err == nil {
			for name, values := range u.Query() {
				if sensitive(name) {
					secrets = append(secrets, values...)
				}
			}
		}
		var value any
		if json.Unmarshal([]byte(input.Body), &value) == nil {
			walk(value, false)
		} else if strings.HasPrefix(input.ContentType, "application/x-www-form-urlencoded") {
			if values, err := url.ParseQuery(input.Body); err == nil {
				for name, fields := range values {
					if sensitive(name) {
						secrets = append(secrets, fields...)
					}
				}
			}
		}
	}
	return secrets
}

func replayURLRedacted(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	if u.Fragment == "[REDACTED]" {
		return true
	}
	for _, values := range u.Query() {
		for _, value := range values {
			if value == "[REDACTED]" {
				return true
			}
		}
	}
	return false
}

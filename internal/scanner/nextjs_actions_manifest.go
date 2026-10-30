package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const nextjsActionsVersion = "nextjs-actions-v1"
const nextjsForeignOrigin = "https://xalgorix.invalid"

// NextjsActionFixture describes an exact observed header-based action call and
// synthetic state oracle. Bodies are separate immutable fixture references.
type NextjsActionFixture struct {
	URL                string `json:"url"`
	ActionID           string `json:"action_id"`
	BodyRef            string `json:"body_ref"`
	ContentType        string `json:"content_type"`
	VerificationURL    string `json:"verification_url"`
	ReadyMarker        string `json:"ready_marker"`
	ChangedMarker      string `json:"changed_marker"`
	CleanupURL         string `json:"cleanup_url"`
	CleanupMethod      string `json:"cleanup_method"`
	CleanupBodyRef     string `json:"cleanup_body_ref,omitempty"`
	CleanupContentType string `json:"cleanup_content_type,omitempty"`
}

var nextjsActionIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{40,64}$`)

// ValidateNextjsActionManifest is shared by plan preview and execution. It
// validates metadata only; it never contacts the target or follows a redirect.
func ValidateNextjsActionManifest(raw []byte, target string, scope assessment.AppScope) (NextjsActionFixture, error) {
	var f NextjsActionFixture
	if len(raw) == 0 || len(raw) > 64<<10 || !json.Valid(raw) {
		return f, fmt.Errorf("action manifest must be a bounded JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return f, fmt.Errorf("action manifest contains invalid or unsupported fields")
	}
	mediaType, _, err := mime.ParseMediaType(f.ContentType)
	if err != nil || (mediaType != "text/plain" && mediaType != "application/x-www-form-urlencoded") || !nextjsActionIDPattern.MatchString(f.ActionID) || !validNextjsBodyRef(f.BodyRef) {
		return f, fmt.Errorf("action manifest requires a supported content type, observed hexadecimal action ID, and request body reference")
	}
	if len(f.ReadyMarker) < 8 || len(f.ReadyMarker) > 2000 || len(f.ChangedMarker) < 8 || len(f.ChangedMarker) > 2000 || strings.Contains(f.ReadyMarker, f.ChangedMarker) || strings.Contains(f.ChangedMarker, f.ReadyMarker) {
		return f, fmt.Errorf("action verification requires distinct non-overlapping controlled state markers of 8 to 2000 bytes")
	}
	if f.CleanupMethod != http.MethodDelete && f.CleanupMethod != http.MethodPut && f.CleanupMethod != http.MethodPatch {
		return f, fmt.Errorf("action cleanup must use an exact DELETE, PUT, or PATCH request")
	}
	if f.CleanupBodyRef != "" && (!validNextjsBodyRef(f.CleanupBodyRef) || f.CleanupContentType == "") {
		return f, fmt.Errorf("cleanup body requires a fixture reference and content type")
	}
	if f.CleanupMethod != http.MethodDelete && f.CleanupBodyRef == "" {
		return f, fmt.Errorf("PUT and PATCH cleanup require a body fixture")
	}
	if f.CleanupContentType != "" {
		if _, _, err := mime.ParseMediaType(f.CleanupContentType); err != nil {
			return f, fmt.Errorf("cleanup content type is invalid")
		}
	}
	base, err := url.Parse(target)
	if err != nil || base.Host == "" || base.User != nil {
		return f, fmt.Errorf("action target must be an HTTP(S) origin")
	}
	for _, destination := range []struct{ method, raw string }{{http.MethodPost, f.URL}, {http.MethodGet, f.VerificationURL}, {f.CleanupMethod, f.CleanupURL}} {
		u, err := url.Parse(destination.raw)
		if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || !sameNextjsOrigin(base, u) {
			return f, fmt.Errorf("action, verification, and cleanup URLs must belong to the original target origin")
		}
		if allowed, _ := scope.Allows(destination.raw); !allowed {
			return f, fmt.Errorf("action, verification, or cleanup URL is outside the approved path scope")
		}
		if excluded, _ := scope.Excluded(destination.method, destination.raw); excluded {
			return f, fmt.Errorf("action, verification, or cleanup request is excluded")
		}
		if destination.method == http.MethodGet && nextjsUnsafeRouteName.MatchString(u.Path) {
			return f, fmt.Errorf("verification URL suggests a state-changing GET")
		}
	}
	return f, nil
}

func sameNextjsOrigin(a, b *url.URL) bool {
	origin := func(u *url.URL) string {
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return strings.ToLower(u.Scheme+"://"+u.Hostname()) + ":" + port
	}
	return origin(a) == origin(b)
}

func validNextjsBodyRef(ref string) bool {
	return len(ref) == 64 && regexpNextjsFixtureRef.MatchString(ref)
}

var regexpNextjsFixtureRef = regexp.MustCompile(`^[a-f0-9]{64}$`)

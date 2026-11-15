package assessment

import (
	"regexp"
	"strings"
	"time"
)

// SystemTemplate captures the reusable SHAPE of a microservice system: one base
// host, many services at a path prefix (for example NestJS services at
// /svc/<name>/*), a predictable per-service OpenAPI path, and one shared token
// that authenticates all of them.
//
// A template stores ONLY the convention — URL patterns and the auth header
// name/prefix. It never stores a secret. The token or password is supplied per
// run and lives in the encrypted credential vault, never in a template.
type SystemTemplate struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// BaseURL is the system's origin, for example https://dev-emis.systems.gov.bt.
	BaseURL string `json:"base_url"`
	// PathTemplate maps a service name to its path, for example "/svc/{name}".
	// It must contain exactly one {name} placeholder.
	PathTemplate string `json:"path_template"`
	// VerifyTemplate maps a service name to a protected path used to prove the
	// shared token works on that service, for example "/svc/{name}/health". It is
	// optional, but without it each service is reported "token applied, not
	// verified" and authenticated OpenAPI discovery does not run for it.
	VerifyTemplate string `json:"verify_template,omitempty"`
	// SpecMode is "auto" (rely on the engine's /documentation-json probing) or
	// "path" (use SpecTemplate for an explicit per-service spec path). Empty
	// defaults to "auto".
	SpecMode     string `json:"spec_mode,omitempty"`
	SpecTemplate string `json:"spec_template,omitempty"`
	// AuthHeaderName/AuthHeaderPrefix describe how the shared token is sent.
	// NAMES ONLY — never a token value. Empty defaults to "Authorization" and
	// "Bearer ".
	AuthHeaderName   string `json:"auth_header_name,omitempty"`
	AuthHeaderPrefix string `json:"auth_header_prefix,omitempty"`
	// LoginURLTemplate is the optional single login endpoint for token-login mode
	// (an absolute path or full URL). It carries no credentials.
	LoginURLTemplate string    `json:"login_url_template,omitempty"`
	VerifyMarker     string    `json:"verify_marker,omitempty"`
	CreatedAt        time.Time `json:"created_at,omitzero"`
	UpdatedAt        time.Time `json:"updated_at,omitzero"`
}

const maxTemplateNameLen = 128

// DefaultAuthHeaderName and DefaultAuthHeaderPrefix are applied when a template
// leaves the auth header convention blank.
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderPrefix = "Bearer "
)

var (
	headerTokenRe    = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	headerPrefixRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z -]*$`)
	base64RunRe      = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}`)
	controlCharsStr  = "\r\n\x00"
	placeholderToken = "{name}"
)

// WithDefaults returns a copy with the "auto" spec mode and default auth header
// convention filled in. It does not mutate the receiver.
func (t SystemTemplate) WithDefaults() SystemTemplate {
	out := t
	out.Name = strings.TrimSpace(out.Name)
	out.BaseURL = strings.TrimSpace(out.BaseURL)
	out.PathTemplate = strings.TrimSpace(out.PathTemplate)
	out.VerifyTemplate = strings.TrimSpace(out.VerifyTemplate)
	out.SpecTemplate = strings.TrimSpace(out.SpecTemplate)
	out.LoginURLTemplate = strings.TrimSpace(out.LoginURLTemplate)
	out.AuthHeaderName = strings.TrimSpace(out.AuthHeaderName)
	if out.SpecMode = strings.ToLower(strings.TrimSpace(out.SpecMode)); out.SpecMode == "" {
		out.SpecMode = "auto"
	}
	if out.AuthHeaderName == "" {
		out.AuthHeaderName = DefaultAuthHeaderName
	}
	// Preserve a caller-set prefix verbatim (it may legitimately end in a space);
	// only default when entirely empty.
	if strings.TrimSpace(out.AuthHeaderPrefix) == "" && out.AuthHeaderPrefix == "" {
		out.AuthHeaderPrefix = DefaultAuthHeaderPrefix
	}
	return out
}

// Validate reports blocking problems with a template. It enforces that templates
// carry conventions only (no secret-looking values) so a token can never be
// persisted in one.
func (t SystemTemplate) Validate() []Problem {
	t = t.WithDefaults()
	var problems []Problem
	add := func(code, msg string) { problems = append(problems, blocking("system_template."+code, msg)) }

	if t.Name == "" || len(t.Name) > maxTemplateNameLen || strings.ContainsAny(t.Name, controlCharsStr) {
		add("name", "template name must be 1–128 printable characters")
	}
	if t.BaseURL == "" {
		add("base_url", "base URL is required (for example https://host)")
	} else if _, err := ParseApprovedOrigin("", t.BaseURL); err != nil {
		add("base_url", "base URL must be an absolute http(s) origin: "+err.Error())
	}

	validatePathTemplate(&problems, add, "path_template", t.PathTemplate, true)
	if t.VerifyTemplate != "" {
		validatePathTemplate(&problems, add, "verify_template", t.VerifyTemplate, true)
	} else {
		problems = append(problems, advisory("system_template.verify_template",
			"no verify path: services will be reported applied-but-not-verified and authenticated OpenAPI discovery will not run for them"))
	}

	switch t.SpecMode {
	case "auto":
		if t.SpecTemplate != "" {
			add("spec_template", "spec_template must be empty when spec_mode is \"auto\"")
		}
	case "path":
		validatePathTemplate(&problems, add, "spec_template", t.SpecTemplate, true)
	default:
		add("spec_mode", "spec_mode must be \"auto\" or \"path\"")
	}

	if !headerTokenRe.MatchString(t.AuthHeaderName) {
		add("auth_header_name", "auth header name must be a header token (letters, digits, hyphen), not a value")
	}
	if p := t.AuthHeaderPrefix; p != "" {
		if len(p) > 16 || !headerPrefixRe.MatchString(strings.TrimRight(p, " ")) {
			add("auth_header_prefix", "auth header prefix must be a short scheme word such as \"Bearer \", not a token")
		}
	}
	if t.LoginURLTemplate != "" {
		if strings.ContainsAny(t.LoginURLTemplate, controlCharsStr) ||
			!(strings.HasPrefix(t.LoginURLTemplate, "/") || strings.Contains(t.LoginURLTemplate, "://")) {
			add("login_url_template", "login URL template must be an absolute path or full URL")
		}
	}

	// Defence in depth: no field may carry anything that looks like a secret.
	// A template stores conventions only; the token is supplied per run.
	for field, value := range map[string]string{
		"base_url": t.BaseURL, "path_template": t.PathTemplate, "verify_template": t.VerifyTemplate,
		"spec_template": t.SpecTemplate, "login_url_template": t.LoginURLTemplate,
		"auth_header_prefix": t.AuthHeaderPrefix, "verify_marker": t.VerifyMarker,
	} {
		if looksLikeSecret(value) {
			add(field, "value looks like it contains a secret; templates store conventions only — supply the token per run")
		}
	}
	return problems
}

func validatePathTemplate(problems *[]Problem, add func(code, msg string), field, value string, requirePlaceholder bool) {
	if value == "" {
		add(field, field+" is required (for example /svc/{name})")
		return
	}
	if !strings.HasPrefix(value, "/") {
		add(field, field+" must be an absolute path starting with /")
	}
	if strings.ContainsAny(value, controlCharsStr) || strings.ContainsAny(value, "?#") || strings.Contains(value, "://") {
		add(field, field+" must be a path without scheme, query or fragment")
	}
	if requirePlaceholder && strings.Count(value, placeholderToken) != 1 {
		add(field, field+" must contain exactly one {name} placeholder")
	}
}

// looksLikeSecret flags values that resemble a credential: a JWT, or a long
// unbroken high-entropy run that is not an ordinary URL/path.
func looksLikeSecret(value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(value, "eyJ") { // JWT header "{" base64url
		return true
	}
	// Ignore the parts of a URL/path that are legitimately long (host, segments).
	stripped := strings.NewReplacer("/", " ", ".", " ", ":", " ", "{name}", " ").Replace(value)
	for _, run := range base64RunRe.FindAllString(stripped, -1) {
		if len(run) >= 24 {
			return true
		}
	}
	return false
}

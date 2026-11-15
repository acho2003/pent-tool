package assessment

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ExpandedService is one service produced by expanding a SystemTemplate over a
// service name.
type ExpandedService struct {
	Name       string `json:"name"`
	ServiceID  string `json:"service_id"`
	TargetID   string `json:"target_id"`
	URL        string `json:"url"`
	VerifyURL  string `json:"verify_url,omitempty"`  // full URL, for a CLI AccessBinding
	VerifyPath string `json:"verify_path,omitempty"` // path, for the web import row
	SpecPath   string `json:"spec_path,omitempty"`   // path, when SpecMode=="path"
}

// Expansion is the result of expanding a SystemTemplate over a list of service
// names. It is a pure data product: no targets are scanned and no scope is
// computed here (a URL target's path boundary is derived automatically from its
// value by AppScopeForTarget).
type Expansion struct {
	Targets       []Target          `json:"targets"`
	Services      []Service         `json:"services"`
	VerifyByID    map[string]string `json:"verify_by_id,omitempty"`
	AuthTargetIDs []string          `json:"auth_target_ids"`
	HeaderName    string            `json:"header_name"`
	HeaderPrefix  string            `json:"header_prefix"`
	Items         []ExpandedService `json:"items"`
}

var slugCleanRe = regexp.MustCompile(`[^a-z0-9]+`)

// ExpandSystemTemplate turns a template plus a list of operator-supplied service
// names into path-scoped URL targets, service groupings, and per-service verify
// URLs. It is PURE: no I/O, deterministic ordering, no network.
//
// It never emits AccessBindings or credential IDs — the caller (web or CLI)
// attaches the credential it owns, one binding per target with that target's own
// verify URL, so per-service verification is preserved.
func ExpandSystemTemplate(t SystemTemplate, serviceNames []string, baseOverride string) (Expansion, error) {
	t = t.WithDefaults()
	if probs := t.Validate(); FirstBlocking(probs) != nil {
		return Expansion{}, fmt.Errorf("invalid system template: %s", FirstBlocking(probs).Message)
	}

	base := strings.TrimSpace(baseOverride)
	if base == "" {
		base = t.BaseURL
	}
	if _, err := ParseApprovedOrigin("", base); err != nil {
		return Expansion{}, fmt.Errorf("invalid base URL %q: %w", base, err)
	}
	base = strings.TrimRight(base, "/")

	exp := Expansion{
		VerifyByID:   map[string]string{},
		HeaderName:   t.AuthHeaderName,
		HeaderPrefix: t.AuthHeaderPrefix,
	}
	seenName := map[string]bool{}
	seenSlug := map[string]bool{}
	count := 0

	for _, raw := range serviceNames {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, controlCharsStr) {
			return Expansion{}, fmt.Errorf("service name %q contains control characters", raw)
		}
		key := strings.ToLower(name)
		if seenName[key] {
			continue // dedupe, first occurrence wins
		}
		seenName[key] = true

		slug := slugify(name)
		if slug == "" {
			return Expansion{}, fmt.Errorf("service name %q has no usable identifier characters", name)
		}
		if seenSlug[slug] {
			return Expansion{}, fmt.Errorf("service names collide on identifier %q (for example from %q)", slug, name)
		}
		seenSlug[slug] = true

		count++
		if count > maxExpandedServices {
			return Expansion{}, fmt.Errorf("more than %d services requested", maxExpandedServices)
		}

		svcURL := base + applyNameTemplate(t.PathTemplate, name)
		if err := validateAbsoluteHTTPURL(svcURL); err != nil {
			return Expansion{}, fmt.Errorf("service %q produced an invalid URL %q: %w", name, svcURL, err)
		}
		targetID := "svc-" + slug + "-url"
		serviceID := "svc-" + slug

		item := ExpandedService{Name: name, ServiceID: serviceID, TargetID: targetID, URL: svcURL}
		if t.VerifyTemplate != "" {
			item.VerifyPath = applyNameTemplate(t.VerifyTemplate, name)
			verifyURL := base + item.VerifyPath
			if err := validateAbsoluteHTTPURL(verifyURL); err != nil {
				return Expansion{}, fmt.Errorf("service %q produced an invalid verify URL %q: %w", name, verifyURL, err)
			}
			item.VerifyURL = verifyURL
			exp.VerifyByID[targetID] = verifyURL
		}
		if t.SpecMode == "path" {
			item.SpecPath = applyNameTemplate(t.SpecTemplate, name)
		}

		exp.Targets = append(exp.Targets, Target{ID: targetID, Kind: KindURL, Value: svcURL})
		exp.Services = append(exp.Services, Service{ID: serviceID, Name: name, TargetIDs: []string{targetID}})
		exp.AuthTargetIDs = append(exp.AuthTargetIDs, targetID)
		exp.Items = append(exp.Items, item)
	}

	if len(exp.Items) == 0 {
		return Expansion{}, fmt.Errorf("no service names supplied")
	}
	return exp, nil
}

const maxExpandedServices = maxImportedServicesLimit

// maxImportedServicesLimit mirrors the web services-import cap so a template
// expansion cannot produce more targets than a CSV import would.
const maxImportedServicesLimit = 500

func applyNameTemplate(tmpl, name string) string {
	return strings.ReplaceAll(tmpl, placeholderToken, name)
}

func slugify(name string) string {
	return strings.Trim(slugCleanRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

func validateAbsoluteHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain userinfo")
	}
	return nil
}

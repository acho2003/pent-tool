package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

const nextjsBoundariesVersion = "nextjs-boundaries-v1"

// NextjsBoundaryFixture holds exact controlled resources; never inferred scope.
type NextjsBoundaryFixture struct {
	Kind                   string `json:"kind"`
	URL                    string `json:"url"`
	Representation         string `json:"representation,omitempty"`
	ConsumerRepresentation string `json:"consumer_representation,omitempty"`
	PrivateMarker          string `json:"private_marker,omitempty"`
	DeniedMarker           string `json:"denied_marker,omitempty"`
	BypassURL              string `json:"bypass_url,omitempty"`
	Isolated               bool   `json:"isolated,omitempty"`
	CleanupURL             string `json:"cleanup_url,omitempty"`
	CleanupMethod          string `json:"cleanup_method,omitempty"`
	CleanupBodyRef         string `json:"cleanup_body_ref,omitempty"`
	CleanupContentType     string `json:"cleanup_content_type,omitempty"`
	Parameter              string `json:"parameter,omitempty"`
	ControlValue           string `json:"control_value,omitempty"`
	DestinationURL         string `json:"destination_url,omitempty"`
	CallbackURL            string `json:"callback_url,omitempty"`
	EventsURL              string `json:"events_url,omitempty"`
}

// ValidateNextjsBoundaryManifest never resolves a host or contacts a target.
func ValidateNextjsBoundaryManifest(raw []byte, target string, scope assessment.AppScope) (NextjsBoundaryFixture, error) {
	var f NextjsBoundaryFixture
	if len(raw) == 0 || len(raw) > 64<<10 || !json.Valid(raw) {
		return f, fmt.Errorf("boundary manifest must be bounded JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return f, fmt.Errorf("boundary manifest contains unsupported fields")
	}
	base, err := url.Parse(target)
	if err != nil || base.Host == "" || base.User != nil {
		return f, fmt.Errorf("boundary target is invalid")
	}
	check := func(raw, method string, original bool) (*url.URL, error) {
		u, err := url.Parse(raw)
		if err != nil || len(raw) > 8192 || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("boundary URLs must be bounded HTTP(S) destinations without credentials or fragments")
		}
		if original && !sameNextjsOrigin(base, u) {
			return nil, fmt.Errorf("boundary resource or cleanup is outside the original target origin")
		}
		if ok, _ := scope.Allows(raw); !ok {
			return nil, fmt.Errorf("boundary destination is outside explicitly approved scope")
		}
		if excluded, _ := scope.Excluded(method, raw); excluded {
			return nil, fmt.Errorf("boundary request is excluded")
		}
		if method == http.MethodGet && nextjsUnsafeRouteName.MatchString(u.Path) {
			return nil, fmt.Errorf("boundary GET path suggests a state-changing operation")
		}
		return u, nil
	}
	resource, err := check(f.URL, "GET", true)
	if err != nil {
		return f, err
	}
	if f.Kind != "cache" && (f.Representation != "" || f.ConsumerRepresentation != "" || f.PrivateMarker != "" || f.DeniedMarker != "" || f.BypassURL != "" || f.Isolated || f.CleanupURL != "" || f.CleanupMethod != "" || f.CleanupBodyRef != "" || f.CleanupContentType != "") {
		return f, fmt.Errorf("cache/reset fields are unsupported for URL probes")
	}
	if f.Kind == "cache" && (f.Parameter != "" || f.ControlValue != "" || f.DestinationURL != "" || f.CallbackURL != "" || f.EventsURL != "") {
		return f, fmt.Errorf("URL-probe fields are unsupported for cache tests")
	}
	if f.Kind == "proxy" && (f.ControlValue != "" || f.DestinationURL != "") {
		return f, fmt.Errorf("redirect controls are unsupported for proxy tests")
	}
	if f.Kind == "redirect" && (f.CallbackURL != "" || f.EventsURL != "") {
		return f, fmt.Errorf("callback event fields are unsupported for redirect tests")
	}
	switch f.Kind {
	case "cache":
		validRepresentation := func(value string) bool { return value == "html" || value == "pages-json" || value == "rsc" }
		if f.ConsumerRepresentation == "" {
			f.ConsumerRepresentation = f.Representation
		}
		if !f.Isolated || !validRepresentation(f.Representation) || !validRepresentation(f.ConsumerRepresentation) || len(f.PrivateMarker) < 8 || len(f.PrivateMarker) > 2000 || len(f.DeniedMarker) < 8 || len(f.DeniedMarker) > 2000 || strings.Contains(f.PrivateMarker, f.DeniedMarker) || strings.Contains(f.DeniedMarker, f.PrivateMarker) {
			return f, fmt.Errorf("cache probes require isolated controlled data, supported response formats, and non-overlapping private/denied markers")
		}
		bypass, err := check(f.BypassURL, "GET", true)
		if err != nil {
			return f, err
		}
		if bypass.EscapedPath() != resource.EscapedPath() || bypass.RawQuery == resource.RawQuery {
			return f, fmt.Errorf("cache bypass control must use the same resource path and a distinct supplied query")
		}
		if f.CleanupMethod != "DELETE" && f.CleanupMethod != "PUT" && f.CleanupMethod != "PATCH" {
			return f, fmt.Errorf("cache reset requires DELETE, PUT, or PATCH cleanup")
		}
		if _, err := check(f.CleanupURL, f.CleanupMethod, true); err != nil {
			return f, err
		}
		if f.CleanupBodyRef != "" && (!validNextjsBodyRef(f.CleanupBodyRef) || f.CleanupContentType == "") {
			return f, fmt.Errorf("cache cleanup body requires a valid fixture reference and content type")
		}
		if f.CleanupContentType != "" {
			if _, _, err := mime.ParseMediaType(f.CleanupContentType); err != nil {
				return f, fmt.Errorf("cache cleanup content type is invalid")
			}
		}
		if f.CleanupMethod != "DELETE" && f.CleanupBodyRef == "" {
			return f, fmt.Errorf("PUT/PATCH cache cleanup requires a body fixture")
		}
	case "redirect", "proxy":
		values, err := url.ParseQuery(resource.RawQuery)
		if err != nil || f.Parameter == "" || len(f.Parameter) > 128 || len(values[f.Parameter]) != 1 {
			return f, fmt.Errorf("URL probes require one exact observed query parameter")
		}
		if f.Kind == "redirect" {
			control, err := resource.Parse(f.ControlValue)
			if err != nil || f.ControlValue == "" || !sameNextjsOrigin(base, control) || control.User != nil || control.Fragment != "" || values.Get(f.Parameter) != f.ControlValue {
				return f, fmt.Errorf("redirect control must match the observed local query value")
			}
			if _, err := check(control.String(), "GET", true); err != nil {
				return f, err
			}
			destination, err := check(f.DestinationURL, "GET", false)
			if err != nil {
				return f, err
			}
			if sameNextjsOrigin(base, destination) || destination.RawQuery != "" {
				return f, fmt.Errorf("redirect destination must be an explicitly scoped external URL without a query")
			}
		} else {
			callback, err := check(f.CallbackURL, "GET", false)
			if err != nil {
				return f, err
			}
			events, err := check(f.EventsURL, "GET", false)
			if err != nil {
				return f, err
			}
			if !sameNextjsOrigin(callback, events) || sameNextjsOrigin(base, callback) || callback.RawQuery != "" || events.RawQuery != "" || callback.EscapedPath() == events.EscapedPath() {
				return f, fmt.Errorf("callback and event URLs must be distinct query-free paths on the same explicitly scoped external origin")
			}
		}
	default:
		return f, fmt.Errorf("unsupported boundary kind")
	}
	return f, nil
}

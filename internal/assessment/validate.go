package assessment

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Problem is a single validation finding. Code is a stable machine identifier;
// Message is human-readable. Blocking distinguishes hard errors (reject) from
// advisories the caller may surface as warnings.
type Problem struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Blocking bool   `json:"blocking"`
}

func blocking(code, msg string) Problem { return Problem{Code: code, Message: msg, Blocking: true} }
func advisory(code, msg string) Problem { return Problem{Code: code, Message: msg, Blocking: false} }

// Normalize returns a copy of cfg with enums upper-cased/trimmed, duplicate
// types removed (order preserved), scanner-selection mode defaulted to "auto",
// and targets given stable IDs where missing. Target values keep their original
// case and form; only surrounding whitespace is trimmed.
func Normalize(cfg AssessmentConfig) AssessmentConfig {
	out := cfg
	out.Mode = Mode(strings.ToUpper(strings.TrimSpace(string(cfg.Mode))))

	seen := map[Type]bool{}
	out.Types = nil
	for _, t := range cfg.Types {
		nt := Type(strings.ToUpper(strings.TrimSpace(string(t))))
		if nt == "" || seen[nt] {
			continue
		}
		seen[nt] = true
		out.Types = append(out.Types, nt)
	}

	out.Targets = make([]Target, len(cfg.Targets))
	for i, tgt := range cfg.Targets {
		nt := tgt
		nt.Kind = TargetKind(strings.ToUpper(strings.TrimSpace(string(tgt.Kind))))
		nt.Value = strings.TrimSpace(tgt.Value)
		nt.ID = strings.TrimSpace(tgt.ID)
		if nt.ID == "" {
			nt.ID = fmt.Sprintf("t%d", i+1)
		}
		out.Targets[i] = nt
	}

	out.Access = make([]AccessBinding, len(cfg.Access))
	for i, ab := range cfg.Access {
		nb := ab
		nb.Kind = AccessKind(strings.ToUpper(strings.TrimSpace(string(ab.Kind))))
		out.Access[i] = nb
	}
	seenDefinitions := map[string]bool{}
	out.APIDefinitionIDs = nil
	for _, id := range cfg.APIDefinitionIDs {
		id = strings.TrimSpace(id)
		if !seenDefinitions[id] {
			seenDefinitions[id] = true
			out.APIDefinitionIDs = append(out.APIDefinitionIDs, id)
		}
	}
	seenBindings := map[string]bool{}
	out.APIDefinitions = nil
	for _, binding := range cfg.APIDefinitions {
		binding.TargetID = strings.TrimSpace(binding.TargetID)
		binding.DefinitionID = strings.TrimSpace(binding.DefinitionID)
		key := binding.TargetID + "\x00" + binding.DefinitionID
		if !seenBindings[key] {
			seenBindings[key] = true
			out.APIDefinitions = append(out.APIDefinitions, binding)
		}
	}

	mode := strings.ToLower(strings.TrimSpace(out.ScannerSelection.Mode))
	if mode == "" {
		mode = "auto"
	}
	out.ScannerSelection.Mode = mode
	return out
}

// internalAccessKind reports whether an access kind implies non-public
// (credentialed / internal) access that Black Box forbids.
func internalAccessKind(k AccessKind) bool {
	switch k {
	case AccessApplicationHeaders, AccessApplicationCookies, AccessBearerToken,
		AccessAPIKey, AccessFormLogin, AccessRepositoryCreds, AccessSSH,
		AccessWindows, AccessCloud, AccessKubernetes:
		return true
	default:
		return false
	}
}

// internalResourceKind reports whether a target kind is an internal resource
// (source tree, image, cluster, cloud account) as opposed to an external
// network/web/API/schema target.
func internalResourceKind(k TargetKind) bool {
	switch k {
	case KindRepository, KindLocalSourcePath, KindDockerImage,
		KindCloudAccount, KindKubernetesCluster:
		return true
	default:
		return false
	}
}

// Validate checks a NORMALIZED config against enum validity, target boundaries,
// and the mode/access policy table (§5). It returns all problems found; callers
// reject when any problem is Blocking.
func Validate(cfg AssessmentConfig) []Problem {
	var probs []Problem

	if !cfg.Mode.Valid() {
		probs = append(probs, blocking("mode.invalid",
			fmt.Sprintf("assessment_mode %q must be BLACK_BOX, GRAY_BOX, or WHITE_BOX", cfg.Mode)))
	}
	if len(cfg.Types) == 0 {
		probs = append(probs, blocking("types.empty", "assessment_types must list at least one type"))
	}
	for _, t := range cfg.Types {
		if !t.Valid() {
			probs = append(probs, blocking("types.invalid", fmt.Sprintf("unknown assessment type %q", t)))
		}
	}
	if len(cfg.Targets) == 0 {
		probs = append(probs, blocking("targets.empty", "assessment_targets must list at least one target"))
	}
	ids := map[string]bool{}
	for _, tgt := range cfg.Targets {
		if !tgt.Kind.Valid() {
			probs = append(probs, blocking("target.kind.invalid",
				fmt.Sprintf("target %q has unknown kind %q", tgt.ID, tgt.Kind)))
		}
		if strings.TrimSpace(tgt.Value) == "" {
			probs = append(probs, blocking("target.value.empty", fmt.Sprintf("target %q has an empty value", tgt.ID)))
		} else if err := validateTargetValue(tgt); err != nil {
			probs = append(probs, blocking("target.value.invalid", fmt.Sprintf("target %q: %v", tgt.ID, err)))
		}
		if ids[tgt.ID] {
			probs = append(probs, blocking("target.id.duplicate", fmt.Sprintf("duplicate target id %q", tgt.ID)))
		}
		ids[tgt.ID] = true
	}

	// Access bindings must reference known targets and valid kinds.
	for _, ab := range cfg.Access {
		if !ab.Kind.Valid() {
			probs = append(probs, blocking("access.kind.invalid", fmt.Sprintf("unknown access kind %q", ab.Kind)))
		}
		if ab.Kind == AccessFormLogin && len(ab.TargetIDs) != 1 {
			probs = append(probs, blocking("access.form_login.single_target", "form login must be bound to exactly one application target"))
		}
		if len(ab.TargetIDs) == 0 {
			probs = append(probs, blocking("access.unbound", fmt.Sprintf("access binding %q lists no target_ids", ab.Kind)))
		}
		if ab.Kind == AccessApplicationHeaders || ab.Kind == AccessApplicationCookies || ab.Kind == AccessBearerToken || ab.Kind == AccessAPIKey || ab.Kind == AccessFormLogin {
			if strings.TrimSpace(ab.CredentialID) != "" {
				if strings.TrimSpace(ab.VerifyURL) == "" || strings.TrimSpace(ab.VerifyMarker) == "" {
					probs = append(probs, blocking("access.verification_required", "application credentials require an in-scope verify_url and expected verify_marker"))
				} else if err := validateTargetValue(Target{Kind: KindURL, Value: ab.VerifyURL}); err != nil {
					probs = append(probs, blocking("access.verify_url.invalid", "credential verification URL must be an absolute HTTP(S) URL without embedded credentials or fragments"))
				}
				if len(ab.VerifyMarker) > 256 || strings.ContainsAny(ab.VerifyMarker, "\r\n\x00") {
					probs = append(probs, blocking("access.verify_marker.invalid", "credential verification marker must be 1–256 printable characters"))
				}
			}
		}
		for _, id := range ab.TargetIDs {
			if !ids[id] {
				probs = append(probs, blocking("access.target.unknown",
					fmt.Sprintf("access binding %q references unknown target id %q", ab.Kind, id)))
			}
			if ab.Kind == AccessApplicationHeaders || ab.Kind == AccessApplicationCookies || ab.Kind == AccessBearerToken || ab.Kind == AccessAPIKey || ab.Kind == AccessFormLogin {
				for _, target := range cfg.Targets {
					if target.ID == id && target.Kind != KindURL {
						probs = append(probs, blocking("access.target_must_be_url", fmt.Sprintf("application credential target %q must be an explicit URL", id)))
					} else if target.ID == id && ab.VerifyURL != "" && !verificationURLWithinTarget(target.Value, ab.VerifyURL) {
						probs = append(probs, blocking("access.verify_url.out_of_scope", fmt.Sprintf("verification URL for target %q must use the same origin and remain under its path boundary", id)))
					}
				}
			}
		}
	}
	if len(cfg.APIDefinitionIDs) > 0 && len(cfg.APIDefinitions) > 0 {
		probs = append(probs, blocking("api_definition.ambiguous", "use api_definitions target bindings or api_definition_ids, not both"))
	}
	if len(cfg.APIDefinitionIDs) > 0 && len(cfg.Targets) != 1 {
		probs = append(probs, blocking("api_definition.target_required", "unbound api_definition_ids require exactly one assessment target; use api_definitions for multi-target assessments"))
	}
	for _, id := range cfg.APIDefinitionIDs {
		if strings.TrimSpace(id) == "" {
			probs = append(probs, blocking("api_definition.id_empty", "api_definition_ids cannot contain an empty ID"))
		}
	}
	for _, binding := range cfg.APIDefinitions {
		if !ids[binding.TargetID] {
			probs = append(probs, blocking("api_definition.target_unknown", fmt.Sprintf("API definition references unknown target id %q", binding.TargetID)))
		}
		if binding.DefinitionID == "" {
			probs = append(probs, blocking("api_definition.id_empty", "API definition binding requires a definition_id"))
		}
		for _, target := range cfg.Targets {
			if target.ID == binding.TargetID && target.Kind != KindURL {
				probs = append(probs, blocking("api_definition.target_must_be_url", fmt.Sprintf("API definition target %q must be an explicit URL with scheme, host, port, and path", target.ID)))
			}
		}
	}
	if len(cfg.APIDefinitionIDs) > 0 && len(cfg.Targets) == 1 && cfg.Targets[0].Kind != KindURL {
		probs = append(probs, blocking("api_definition.target_must_be_url", "unbound API definition requires one explicit URL target"))
	}

	probs = append(probs, validateModePolicy(cfg)...)
	return probs
}

func verificationURLWithinTarget(targetURL, verifyURL string) bool {
	target, targetErr := url.Parse(targetURL)
	verify, verifyErr := url.Parse(verifyURL)
	if targetErr != nil || verifyErr != nil || target.Host == "" || verify.Host == "" || !strings.EqualFold(target.Scheme, verify.Scheme) || !strings.EqualFold(target.Host, verify.Host) || verify.User != nil || verify.Fragment != "" || verify.RawQuery != "" {
		return false
	}
	base := strings.TrimSuffix(target.EscapedPath(), "/")
	path := verify.EscapedPath()
	return base == "" || path == base || strings.HasPrefix(path, base+"/")
}

func validateTargetValue(target Target) error {
	value := strings.TrimSpace(target.Value)
	switch target.Kind {
	case KindURL:
		u, err := url.Parse(value)
		if err != nil || !u.IsAbs() || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("URL targets must be absolute HTTP(S) URLs without embedded credentials or fragments")
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("URL target has an invalid port")
			}
		}
	case KindIP:
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("IP targets must contain one IPv4 or IPv6 address")
		}
	case KindCIDR:
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("CIDR targets must contain a valid network prefix")
		}
	case KindDomain:
		if strings.ContainsAny(value, "/:? #") || value == "" {
			return fmt.Errorf("domain targets must be hostnames without a scheme, port, path, query, or fragment")
		}
	case KindHost:
		if strings.ContainsAny(value, "/?#") {
			return fmt.Errorf("host targets must not include a URL path, query, or fragment")
		}
	}
	return nil
}

func validateModePolicy(cfg AssessmentConfig) []Problem {
	var probs []Problem
	switch cfg.Mode {
	case ModeBlackBox:
		for _, ab := range cfg.Access {
			if internalAccessKind(ab.Kind) {
				probs = append(probs, blocking("blackbox.access.forbidden",
					fmt.Sprintf("Black Box forbids credentialed access (%s); use Gray Box or White Box", ab.Kind)))
			}
		}
		for _, tgt := range cfg.Targets {
			if internalResourceKind(tgt.Kind) {
				probs = append(probs, blocking("blackbox.resource.forbidden",
					fmt.Sprintf("Black Box forbids internal resource %q (%s); use White Box", tgt.ID, tgt.Kind)))
			}
		}
	case ModeGrayBox:
		// Gray Box permits external targets, schemas, app credentials, and
		// limited host access, but source trees, container images, and full IaC
		// inputs require White Box in this release.
		for _, tgt := range cfg.Targets {
			switch tgt.Kind {
			case KindRepository, KindLocalSourcePath, KindDockerImage:
				probs = append(probs, blocking("graybox.resource.requires_whitebox",
					fmt.Sprintf("resource %q (%s) requires White Box in this release", tgt.ID, tgt.Kind)))
			case KindCloudAccount, KindKubernetesCluster:
				probs = append(probs, advisory("graybox.resource.unsupported",
					fmt.Sprintf("resource %q (%s) has no runnable adapter yet", tgt.ID, tgt.Kind)))
			}
		}
	case ModeWhiteBox:
		// All supported resource kinds are permitted. Unsupported adapters are
		// surfaced later as unavailable, not rejected here.
	}
	return probs
}

// FirstBlocking returns the first blocking problem, or nil if none.
func FirstBlocking(probs []Problem) *Problem {
	for i := range probs {
		if probs[i].Blocking {
			return &probs[i]
		}
	}
	return nil
}

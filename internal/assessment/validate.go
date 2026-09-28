package assessment

import (
	"fmt"
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
		if len(ab.TargetIDs) == 0 {
			probs = append(probs, blocking("access.unbound", fmt.Sprintf("access binding %q lists no target_ids", ab.Kind)))
		}
		for _, id := range ab.TargetIDs {
			if !ids[id] {
				probs = append(probs, blocking("access.target.unknown",
					fmt.Sprintf("access binding %q references unknown target id %q", ab.Kind, id)))
			}
		}
	}

	probs = append(probs, validateModePolicy(cfg)...)
	return probs
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

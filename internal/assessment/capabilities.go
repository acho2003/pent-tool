package assessment

import "strings"

// DeriveCapabilities computes per-target capability evidence from a NORMALIZED
// config. It is a pure function: it performs no I/O and never probes a target,
// so it only ever yields "declared", "available", or "unavailable" states —
// "verified" requires a runtime probe recorded elsewhere. Capabilities are
// derived per target and never unioned across unrelated targets (§5).
//
// The output order is stable: targets in config order (each emitting its
// intrinsic capabilities), then access bindings in config order.
func DeriveCapabilities(cfg AssessmentConfig) []CapabilityEvidence {
	var out []CapabilityEvidence
	wantAPI := containsType(cfg.Types, TypeAPI)
	for _, tgt := range cfg.Targets {
		switch tgt.Kind {
		case KindDomain:
			out = append(out,
				ev(CapNetwork, tgt.ID, StateDeclared, "domain", "domain establishes network scope"),
				// A domain may produce conditional web discovery jobs, not a proven live web service.
				ev(CapWeb, tgt.ID, StateDeclared, "domain", "domain may resolve to web hosts (discovery required)"))
		case KindIP:
			// A bare IP does not prove a live web service (§5.2).
			out = append(out, ev(CapNetwork, tgt.ID, StateDeclared, "ip", "IP establishes network scope"))
		case KindCIDR:
			out = append(out, ev(CapNetwork, tgt.ID, StateDeclared, "cidr", "CIDR establishes bounded network scope"))
		case KindHost:
			out = append(out,
				ev(CapNetwork, tgt.ID, StateDeclared, "host", "host establishes network scope"),
				ev(CapHost, tgt.ID, StateDeclared, "host", "host target requested for host-level checks"))
		case KindURL:
			out = append(out, ev(CapWeb, tgt.ID, StateAvailable, "url", "explicit HTTP(S) URL is a concrete web target"))
			if wantAPI && isHTTPURL(tgt.Value) {
				out = append(out, ev(CapAPI, tgt.ID, StateAvailable, "url", "URL usable as an API base for API assessment"))
			}
		case KindRepository:
			// Remote repository is conditional until a checkout succeeds (§5.5).
			out = append(out,
				ev(CapSource, tgt.ID, StateDeclared, "repository", "remote repository requires checkout before source access"),
				ev(CapGit, tgt.ID, StateDeclared, "repository", "repository provides Git history once prepared"))
		case KindLocalSourcePath:
			out = append(out, ev(CapSource, tgt.ID, StateDeclared, "local_source", "local source path establishes source access once verified readable"))
		case KindDockerImage:
			out = append(out, ev(CapImage, tgt.ID, StateDeclared, "image", "image reference is conditional until the runtime can pull it"))
		case KindSBOM:
			out = append(out, ev(CapSBOM, tgt.ID, StateAvailable, "sbom", "SBOM resource is directly consumable"))
		case KindCloudAccount:
			out = append(out, ev(CapCloud, tgt.ID, StateUnavailable, "cloud", "no cloud adapter is available in this release"))
		case KindKubernetesCluster:
			out = append(out, ev(CapKubernetes, tgt.ID, StateUnavailable, "kubernetes", "no Kubernetes adapter is available in this release"))
		}

		// A validated schema adds API schema capability for an API assessment (§5.3).
		hasSchema := false
		for _, binding := range cfg.APIDefinitions {
			if binding.TargetID == tgt.ID && binding.DefinitionID != "" {
				hasSchema = true
			}
		}
		if len(cfg.Targets) == 1 && len(cfg.APIDefinitionIDs) > 0 {
			hasSchema = true
		}
		if wantAPI && hasSchema && (tgt.Kind == KindURL || tgt.Kind == KindDomain) {
			out = append(out, ev(CapSchema, tgt.ID, StateDeclared, "api_definition", "uploaded API schema declared for this target"))
		}
	}

	// Access bindings apply only to their named targets (§5.4, §5.8). A
	// credential reference establishes AVAILABLE access; a verification probe
	// (recorded elsewhere) is what makes it VERIFIED.
	for _, ab := range cfg.Access {
		for _, id := range ab.TargetIDs {
			switch ab.Kind {
			case AccessApplicationHeaders, AccessApplicationCookies, AccessBearerToken, AccessAPIKey, AccessFormLogin:
				st := StateDeclared
				prov := "credential_ref"
				reason := "credential reference supplied; verification pending"
				if strings.TrimSpace(ab.CredentialID) != "" {
					st = StateAvailable
				} else {
					reason = "authenticated access requested without a resolvable credential"
				}
				out = append(out, ev(CapAuthWeb, id, st, prov, reason))
			case AccessRepositoryCreds:
				out = append(out, ev(CapGit, id, StateAvailable, "credential_ref", "repository credentials supplied"))
			case AccessSSH:
				out = append(out, ev(CapSSH, id, StateAvailable, "ssh", "SSH access reference bound to host"))
			case AccessWindows:
				out = append(out, ev(CapWindows, id, StateUnavailable, "windows", "no Windows adapter is available in this release"))
			case AccessCloud:
				out = append(out, ev(CapCloud, id, StateUnavailable, "cloud", "no cloud adapter is available in this release"))
			case AccessKubernetes:
				out = append(out, ev(CapKubernetes, id, StateUnavailable, "kubernetes", "no Kubernetes adapter is available in this release"))
			}
		}
	}
	return out
}

func ev(c Capability, targetID string, st EvidenceState, prov, reason string) CapabilityEvidence {
	return CapabilityEvidence{Capability: c, TargetID: targetID, State: st, Provenance: prov, Reason: reason}
}

func containsType(types []Type, want Type) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

func isHTTPURL(v string) bool {
	lv := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://")
}

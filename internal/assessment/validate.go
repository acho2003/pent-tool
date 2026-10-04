package assessment

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
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
		nb.Identity = strings.TrimSpace(ab.Identity)
		nb.Role = strings.TrimSpace(ab.Role)
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

	out.APIOperationInputs = make([]APIOperationInput, 0, len(cfg.APIOperationInputs))
	for _, input := range cfg.APIOperationInputs {
		input.DefinitionID = strings.TrimSpace(input.DefinitionID)
		input.OperationID = strings.TrimSpace(input.OperationID)
		input.RequestBodyRef = strings.ToLower(strings.TrimSpace(input.RequestBodyRef))
		input.PathParams = normalizeInputMap(input.PathParams)
		input.Query = normalizeInputMap(input.Query)
		out.APIOperationInputs = append(out.APIOperationInputs, input)
	}
	sort.Slice(out.APIOperationInputs, func(i, j int) bool {
		a, b := out.APIOperationInputs[i], out.APIOperationInputs[j]
		return a.DefinitionID+"\x00"+a.OperationID < b.DefinitionID+"\x00"+b.OperationID
	})
	out.WriteApprovals = append([]WriteApproval(nil), cfg.WriteApprovals...)
	for i := range out.WriteApprovals {
		a := &out.WriteApprovals[i]
		a.TargetID = strings.TrimSpace(a.TargetID)
		a.Method = strings.ToUpper(strings.TrimSpace(a.Method))
		a.Path = strings.TrimSpace(a.Path)
		a.OperationID = strings.TrimSpace(a.OperationID)
		a.FixtureRef = strings.ToLower(strings.TrimSpace(a.FixtureRef))
		a.CleanupRef = strings.ToLower(strings.TrimSpace(a.CleanupRef))
	}
	sort.Slice(out.WriteApprovals, func(i, j int) bool {
		a, b := out.WriteApprovals[i], out.WriteApprovals[j]
		return a.TargetID+"\x00"+a.Method+"\x00"+a.Path < b.TargetID+"\x00"+b.Method+"\x00"+b.Path
	})
	out.AuthorizationExpectations = append([]AuthorizationExpectation(nil), cfg.AuthorizationExpectations...)
	for i := range out.AuthorizationExpectations {
		e := &out.AuthorizationExpectations[i]
		e.OperationID = strings.TrimSpace(e.OperationID)
		e.Identity = strings.TrimSpace(e.Identity)
		e.Expect = strings.ToLower(strings.TrimSpace(e.Expect))
		e.ResourceFixtureRef = strings.ToLower(strings.TrimSpace(e.ResourceFixtureRef))
	}
	sort.Slice(out.AuthorizationExpectations, func(i, j int) bool {
		a, b := out.AuthorizationExpectations[i], out.AuthorizationExpectations[j]
		return a.OperationID+"\x00"+a.Identity < b.OperationID+"\x00"+b.Identity
	})

	mode := strings.ToLower(strings.TrimSpace(out.ScannerSelection.Mode))
	if mode == "" {
		mode = "auto"
	}
	out.ScannerSelection.Mode = mode

	// Scope/policy fields: canonicalized, sorted and de-duplicated so the
	// persisted config and the plan fingerprint do not depend on input order.
	// Empty inputs stay nil so legacy configs serialise exactly as before.
	var origins []ApprovedOrigin
	for _, o := range cfg.ApprovedOrigins {
		n, _ := normalizeOrigin(o)
		origins = append(origins, n)
	}
	out.ApprovedOrigins = sortDedupeOrigins(origins)
	out.Exclusions = sortDedupeExclusions(normalizeExclusions(cfg.Exclusions))
	out.DiscoveryProviders = normalizeDiscoveryProviders(cfg.DiscoveryProviders)
	out.ManualSeeds = nil
	seenSeeds := map[string]bool{}
	for _, seed := range cfg.ManualSeeds {
		seed = strings.TrimSpace(seed)
		if seed != "" && !seenSeeds[seed] {
			seenSeeds[seed] = true
			out.ManualSeeds = append(out.ManualSeeds, seed)
		}
	}
	sort.Strings(out.ManualSeeds)
	return out
}

func normalizeInputMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key = strings.TrimSpace(key)
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validFixtureRef(ref string) bool {
	decoded, err := hex.DecodeString(ref)
	return err == nil && len(decoded) == 32
}

// normalizeDiscoveryProviders lower-cases provider names, sorts and dedupes the
// subdomain list, maps "none" to "" and collapses an empty selection to nil.
func normalizeDiscoveryProviders(in *DiscoveryProviders) *DiscoveryProviders {
	if in == nil {
		return nil
	}
	out := &DiscoveryProviders{
		Historical: strings.ToLower(strings.TrimSpace(in.Historical)),
		TLS:        strings.ToLower(strings.TrimSpace(in.TLS)),
	}
	if out.Historical == ProviderNone {
		out.Historical = ""
	}
	seen := map[string]bool{}
	for _, p := range in.Subdomain {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && !seen[p] {
			seen[p] = true
			out.Subdomain = append(out.Subdomain, p)
		}
	}
	sort.Strings(out.Subdomain)
	if len(out.Subdomain) == 0 && out.Historical == "" && out.TLS == "" {
		return nil
	}
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
		if ab.Identity != "" && strings.TrimSpace(ab.CredentialID) == "" {
			probs = append(probs, blocking("access.identity.credential_required", fmt.Sprintf("test identity %q requires a credential binding", ab.Identity)))
		}
		if len(ab.Identity) > 128 || len(ab.Role) > 128 || strings.ContainsAny(ab.Identity+ab.Role, "\r\n\x00") {
			probs = append(probs, blocking("access.identity.invalid", "identity and role labels must be at most 128 printable characters"))
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
				if len(ab.NegativeMarker) > 256 || strings.ContainsAny(ab.NegativeMarker, "\r\n\x00") {
					probs = append(probs, blocking("access.negative_marker.invalid", "negative-control marker must be at most 256 printable characters"))
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
					} else if target.ID == id && ab.VerifyURL != "" && !verificationURLWithinScope(AppScopeForTarget(cfg, id), ab.VerifyURL) {
						probs = append(probs, blocking("access.verify_url.out_of_scope", fmt.Sprintf("verification URL for target %q must stay inside its approved origin and path boundary", id)))
					}
				}
			}
		}
	}
	apiDefinitionIDs := map[string]bool{}
	for _, id := range cfg.APIDefinitionIDs {
		apiDefinitionIDs[id] = true
	}
	for _, binding := range cfg.APIDefinitions {
		apiDefinitionIDs[binding.DefinitionID] = true
	}
	apiType := false
	webOrAPIType := false
	for _, typ := range cfg.Types {
		apiType = apiType || typ == TypeAPI
		webOrAPIType = webOrAPIType || typ == TypeAPI || typ == TypeWebApplication
	}
	seenOperationInputs := map[string]bool{}
	for _, input := range cfg.APIOperationInputs {
		key := input.DefinitionID + "\x00" + input.OperationID
		if input.DefinitionID == "" || input.OperationID == "" || !apiDefinitionIDs[input.DefinitionID] {
			probs = append(probs, blocking("api_input.operation.invalid", "API operation inputs must reference a configured definition and operation ID"))
		}
		if seenOperationInputs[key] {
			probs = append(probs, blocking("api_input.operation.duplicate", "an API operation can have only one input record per definition"))
		}
		seenOperationInputs[key] = true
		if !webOrAPIType {
			probs = append(probs, blocking("api_input.type_required", "API operation inputs require WEB_APPLICATION or API assessment coverage"))
		}
		for _, values := range []map[string]string{input.PathParams, input.Query} {
			for name, value := range values {
				if strings.TrimSpace(name) == "" || len(name) > 256 || len(value) > 4096 || strings.ContainsAny(name+value, "\r\n\x00") {
					probs = append(probs, blocking("api_input.value.invalid", "API path/query names and values must be bounded and contain no control characters"))
					break
				}
			}
		}
		if input.RequestBodyRef != "" && !validFixtureRef(input.RequestBodyRef) {
			probs = append(probs, blocking("api_input.fixture.invalid", "request_body_ref must be a SHA-256 API fixture reference"))
		}
	}
	seenWriteApproval := map[string]bool{}
	for _, approval := range cfg.WriteApprovals {
		key := approval.TargetID + "\x00" + approval.Method + "\x00" + approval.Path
		if !cfg.TestEnvironment || cfg.Mode == ModeBlackBox {
			probs = append(probs, blocking("api_write.test_environment_required", "API write approvals require a non-Black-Box test environment"))
		}
		if !apiType || !ids[approval.TargetID] || approval.OperationID == "" {
			probs = append(probs, blocking("api_write.operation.invalid", "write approval requires the API type, a known target, and an operation ID"))
		}
		boundToTarget := false
		for _, binding := range cfg.APIDefinitions {
			boundToTarget = boundToTarget || binding.TargetID == approval.TargetID
		}
		if len(cfg.APIDefinitionIDs) > 0 && len(cfg.Targets) == 1 && cfg.Targets[0].ID == approval.TargetID {
			boundToTarget = true
		}
		if !boundToTarget {
			probs = append(probs, blocking("api_write.definition_required", "write approval target must have a bound API definition"))
		}
		if approval.Method != "POST" && approval.Method != "PUT" && approval.Method != "PATCH" && approval.Method != "DELETE" {
			probs = append(probs, blocking("api_write.method.invalid", "write approval method must be POST, PUT, PATCH, or DELETE"))
		}
		if !strings.HasPrefix(approval.Path, "/") || strings.ContainsAny(approval.Path, "?#\r\n\x00") {
			probs = append(probs, blocking("api_write.path.invalid", "write approval path must be an absolute path without query or fragment"))
		}
		for _, target := range cfg.Targets {
			if target.ID != approval.TargetID {
				continue
			}
			scope := AppScopeForTarget(cfg, target.ID)
			inScope := false
			for _, origin := range scope.Origins() {
				prefix := strings.TrimSuffix(origin.PathPrefix, "/")
				if prefix == "/" {
					prefix = ""
				}
				requestURL := origin.Origin() + prefix + approval.Path
				if ok, _ := scope.Allows(requestURL); ok {
					inScope = true
					if excluded, _ := scope.Excluded(approval.Method, requestURL); excluded {
						probs = append(probs, blocking("api_write.excluded", fmt.Sprintf("write approval %s %s is excluded by application policy", approval.Method, approval.Path)))
					}
				}
			}
			if !inScope {
				probs = append(probs, blocking("api_write.out_of_scope", fmt.Sprintf("write approval path %q is outside target %q application scope", approval.Path, approval.TargetID)))
			}
		}
		if !validFixtureRef(approval.FixtureRef) {
			probs = append(probs, blocking("api_write.fixture.required", "write approval requires a SHA-256 request fixture reference"))
		}
		if approval.Method == "POST" && !validFixtureRef(approval.CleanupRef) {
			probs = append(probs, blocking("api_write.cleanup.required", "POST write approvals require a declared cleanup fixture reference"))
		}
		if seenWriteApproval[key] {
			probs = append(probs, blocking("api_write.duplicate", "duplicate write approval for the same target, method, and path"))
		}
		seenWriteApproval[key] = true
	}
	boundIdentities := map[string]bool{}
	for _, binding := range cfg.Access {
		if binding.Identity != "" {
			boundIdentities[binding.Identity] = true
		}
	}
	expectationIdentities := map[string]map[string]bool{}
	for _, expectation := range cfg.AuthorizationExpectations {
		if expectation.OperationID == "" || expectation.Identity == "" || (expectation.Expect != "allow" && expectation.Expect != "deny") || !validFixtureRef(expectation.ResourceFixtureRef) {
			probs = append(probs, blocking("api_authorization_expectation.invalid", "authorization expectations require an operation ID, identity, allow/deny outcome, and resource fixture reference"))
		}
		if !boundIdentities[expectation.Identity] {
			probs = append(probs, blocking("api_authorization_expectation.identity_unknown", fmt.Sprintf("authorization expectation identity %q has no credential binding", expectation.Identity)))
		}
		if expectationIdentities[expectation.OperationID] == nil {
			expectationIdentities[expectation.OperationID] = map[string]bool{}
		}
		expectationIdentities[expectation.OperationID][expectation.Identity] = true
		if !apiType {
			probs = append(probs, blocking("api_authorization_expectation.type_required", "authorization expectations require the API assessment type"))
		}
	}
	for operationID, identities := range expectationIdentities {
		if len(identities) < 2 {
			probs = append(probs, blocking("api_authorization_expectation.two_identities", fmt.Sprintf("authorization operation %q requires expectations for two distinct identities", operationID)))
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

	probs = append(probs, validateScopePolicy(cfg, ids)...)
	probs = append(probs, validateModePolicy(cfg)...)
	return probs
}

// verificationURLWithinTarget reports whether verifyURL stays inside the
// boundary derived from targetURL (default ports normalized).
func verificationURLWithinTarget(targetURL, verifyURL string) bool {
	return verificationURLWithinScope(AppScopeForTarget(AssessmentConfig{Targets: []Target{{ID: "t", Kind: KindURL, Value: targetURL}}}, "t"), verifyURL)
}

// verificationURLWithinScope reports whether verifyURL is allowed by scope and
// carries no query or fragment (verification requests are fixed GETs).
func verificationURLWithinScope(scope AppScope, verifyURL string) bool {
	verify, err := url.Parse(verifyURL)
	if err != nil || verify.Fragment != "" || verify.RawQuery != "" || strings.HasSuffix(verifyURL, "#") || strings.HasSuffix(verifyURL, "?") {
		return false
	}
	ok, _ := scope.Allows(verifyURL)
	return ok
}

var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// validateScopePolicy checks approved origins, exclusions, discovery provider
// selections and manual seeds of a NORMALIZED config. ids is the set of known
// target IDs.
func validateScopePolicy(cfg AssessmentConfig, ids map[string]bool) []Problem {
	var probs []Problem
	targetKind := map[string]TargetKind{}
	for _, tgt := range cfg.Targets {
		targetKind[tgt.ID] = tgt.Kind
	}

	hasOrigins := map[string]bool{}
	for _, o := range cfg.ApprovedOrigins {
		if !ids[o.TargetID] {
			probs = append(probs, blocking("origin.target.unknown", fmt.Sprintf("approved origin %s references unknown target id %q", o.String(), o.TargetID)))
			continue
		}
		switch targetKind[o.TargetID] {
		case KindURL, KindDomain, KindIP, KindHost:
		default:
			probs = append(probs, blocking("origin.target_kind", fmt.Sprintf("approved origins can only belong to URL, domain, IP or host targets; %q is %s", o.TargetID, targetKind[o.TargetID])))
		}
		if reason := validOrigin(o); reason != "" {
			probs = append(probs, blocking("origin.invalid", fmt.Sprintf("target %q: %s", o.TargetID, reason)))
			continue
		}
		hasOrigins[o.TargetID] = true
	}
	scopes := map[string]AppScope{}
	for _, tgt := range cfg.Targets {
		scopes[tgt.ID] = AppScopeForTarget(cfg, tgt.ID)
		// Once origins are supplied they are authoritative, so the URL target
		// itself must still be inside them or every job against it is out of scope.
		if tgt.Kind == KindURL && hasOrigins[tgt.ID] {
			if ok, _ := scopes[tgt.ID].Allows(tgt.Value); !ok {
				probs = append(probs, blocking("origin.target_not_covered", fmt.Sprintf("target %q URL is outside its approved origins", tgt.ID)))
			}
		}
	}

	for _, e := range cfg.Exclusions {
		if !strings.HasPrefix(e.PathPattern, "/") || strings.ContainsAny(e.PathPattern, "?#") {
			probs = append(probs, blocking("exclusion.invalid", fmt.Sprintf("exclusion path_pattern %q must be an absolute path without query or fragment", e.PathPattern)))
		}
		if e.Method != "" && !httpMethods[e.Method] {
			probs = append(probs, blocking("exclusion.invalid", fmt.Sprintf("exclusion method %q is not an HTTP method", e.Method)))
		}
		if e.TargetID != "" && !ids[e.TargetID] {
			probs = append(probs, blocking("exclusion.target.unknown", fmt.Sprintf("exclusion references unknown target id %q", e.TargetID)))
			continue
		}
		if e.Origin != "" && !exclusionOriginKnown(cfg, scopes, e) {
			probs = append(probs, blocking("exclusion.origin.unknown", fmt.Sprintf("exclusion origin %q is not an approved origin", e.Origin)))
		}
	}

	if cfg.Mode == ModeBlackBox && cfg.TestEnvironment {
		probs = append(probs, blocking("blackbox.test_environment.forbidden", "Black Box cannot declare a test environment; use Gray Box or White Box"))
	}

	if dp := cfg.DiscoveryProviders; dp != nil {
		for _, p := range dp.Subdomain {
			if p != ProviderSubfinder && p != ProviderAmass {
				probs = append(probs, blocking("discovery.subdomain.invalid", fmt.Sprintf("subdomain provider %q must be subfinder or amass", p)))
			}
		}
		if len(dp.Subdomain) > 0 {
			if !cfg.SubdomainDiscovery {
				probs = append(probs, blocking("discovery.subdomain.not_authorized", "subdomain providers require subdomain_discovery to be enabled"))
			}
			hasDomain := false
			for _, tgt := range cfg.Targets {
				hasDomain = hasDomain || tgt.Kind == KindDomain
			}
			if !hasDomain {
				probs = append(probs, blocking("discovery.subdomain.domain_required", "subdomain providers require a domain target"))
			}
		}
		switch dp.Historical {
		case "", ProviderGau, ProviderWaybackurls:
		default:
			probs = append(probs, blocking("discovery.historical.invalid", fmt.Sprintf("historical provider %q must be one of gau, waybackurls or none (waybackurls is an alternative to gau, not an addition)", dp.Historical)))
		}
		switch dp.TLS {
		case "", ProviderTestssl, ProviderSSLyze:
		default:
			probs = append(probs, blocking("discovery.tls.invalid", fmt.Sprintf("TLS provider %q must be testssl or sslyze (sslyze is an alternative to testssl, not an addition)", dp.TLS)))
		}
	}

	for _, seed := range cfg.ManualSeeds {
		if err := validateTargetValue(Target{Kind: KindURL, Value: seed}); err != nil {
			probs = append(probs, blocking("manual_seed.invalid", fmt.Sprintf("manual seed %q must be an absolute HTTP(S) URL without embedded credentials or fragments", seed)))
			continue
		}
		allowed, excluded := false, ""
		for _, tgt := range cfg.Targets {
			if ok, _ := scopes[tgt.ID].Allows(seed); ok {
				allowed = true
				if hit, why := scopes[tgt.ID].Excluded("GET", seed); hit {
					excluded = why
				}
				break
			}
		}
		switch {
		case !allowed:
			probs = append(probs, blocking("manual_seed.out_of_scope", fmt.Sprintf("manual seed %q is outside every target's approved origins", seed)))
		case excluded != "":
			probs = append(probs, blocking("manual_seed.excluded", fmt.Sprintf("manual seed %q is excluded: %s", seed, excluded)))
		}
	}
	return probs
}

// exclusionOriginKnown reports whether an exclusion's Origin is one of the
// approved (or derived) origins of its target, or of any target when the
// exclusion is global.
func exclusionOriginKnown(cfg AssessmentConfig, scopes map[string]AppScope, e Exclusion) bool {
	for _, tgt := range cfg.Targets {
		if e.TargetID != "" && tgt.ID != e.TargetID {
			continue
		}
		for _, o := range scopes[tgt.ID].Origins() {
			if o.Origin() == e.Origin {
				return true
			}
		}
	}
	return false
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
	case KindRepository:
		// One clone URL per target: a comma- or space-joined list would be
		// handed to git as a single nonexistent URL.
		if strings.ContainsAny(value, " \t\r\n,") {
			return fmt.Errorf("repository targets must be a single repository URL; add each repository separately")
		}
		u, err := url.Parse(value)
		if err != nil || strings.ToLower(u.Scheme) != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("repository targets must be HTTPS clone URLs without embedded credentials, query, or fragment")
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

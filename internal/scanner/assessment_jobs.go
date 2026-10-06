package scanner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

// HasAssessmentRunner reports whether a scanner ID has a direct job adapter.
// Legacy recon stubs are intentionally excluded: typed plans must not claim
// that an installed binary can run as an assessment job unless the pipeline
// has a scoped adapter for it.
func HasAssessmentRunner(id string) bool {
	if id == "auth" || id == "katana" || id == "dnsx" || id == "subfinder" || id == "amass" || id == "httpx" || id == "gau" || id == "waybackurls" || id == "sslyze" || id == "apichecks" || id == "apiwrites" {
		return true
	}
	if id == "nmap" || id == "masscan" || id == "nikto" || id == "lynis" || id == "dalfox" || id == "wapiti" || id == "kube-bench" || id == "prowler" || id == "scoutsuite" {
		return true
	}
	for _, runner := range NewPipeline(Config{}).Runners {
		if runner.Name() == id {
			return true
		}
	}
	return false
}

// RunAssessmentJobs executes selected jobs from a server-generated assessment
// plan without invoking legacy recon. The caller must regenerate and validate
// the plan at the trust boundary before calling this method. Conditional jobs
// remain explicit skipped records until a preparation stage resolves them.
func (p *Pipeline) RunAssessmentJobs(ctx context.Context, plan AssessmentPlan, scanDir string, existing []Run, emit EmitFunc) []Run {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(plan.Jobs) > 0 && strings.TrimSpace(plan.Fingerprint) == "" {
		return failedAssessmentJobs(plan.Jobs, scanDir, "", "accepted plan fingerprint is required", emit)
	}
	if UnifiedWorkflowEnabled() && plan.Config.WorkflowVersion == "unified-v1" {
		if _, err := openRequestWriteJournal(Request{WriteJournalDir: scanDir}); err != nil {
			runs := failedAssessmentJobs(plan.Jobs, scanDir, plan.Fingerprint, "write journal recovery failed; automatic resume was refused", emit)
			for i := range runs {
				runs[i].GapKind = GapInterruptedWrite
			}
			return runs
		}
	}
	if unresolved, err := UnresolvedWrites(scanDir); err != nil || len(unresolved) > 0 {
		runs := failedAssessmentJobs(plan.Jobs, scanDir, plan.Fingerprint, "unresolved write journal prevents automatic resume", emit)
		for i := range runs {
			runs[i].GapKind = GapInterruptedWrite
		}
		return runs
	}
	expanded := UnifiedWorkflowEnabled() && plan.Config.WorkflowVersion == "unified-v1"
	if plan.Config.WorkflowVersion == "unified-v1" && !expanded {
		return failedAssessmentJobs(plan.Jobs, scanDir, plan.Fingerprint, "accepted expanded workflow is disabled; executor was not changed", emit)
	}
	if p == nil {
		p = NewPipeline(Config{})
	} else if p.Runners == nil {
		p = NewPipeline(p.Config)
	} else {
		applyDefaults(&p.Config)
	}
	if profileName := strings.TrimSpace(plan.Config.Profile); profileName != "" {
		profile, ok := ResolveWebProfile(profileName)
		if !ok {
			return failedAssessmentJobs(plan.Jobs, scanDir, plan.Fingerprint, "assessment plan contains an unsupported web profile", emit)
		}
		p.Config.WebProfile = profile.Name
		p.Config.RateRPS = profile.RateRPS
		p.Config.WebMaxEndpoints = profile.MaxEndpoints
		p.Config.WebBudget = profile.Budget
		p.Config.WebBrowser = profile.Browser
	}
	var replayStore *credentials.ReplayStore
	if expanded && len(p.Config.ReplayKey) > 0 {
		var err error
		replayStore, err = credentials.NewReplayStore(filepath.Join(scanDir, "request-replay"), p.Config.ReplayKey)
		if err != nil {
			return failedAssessmentJobs(plan.Jobs, scanDir, plan.Fingerprint, "encrypted replay storage unavailable", emit)
		}
	}
	// One budget is shared by discovery and every job in this assessment.
	// Scanner-specific limits still apply inside each adapter.
	p.Config.Budget = NewAssessmentBudget(p.Config.RateRPS, p.Config.WebMaxEndpoints, p.Config.WebBudget)
	appScopes := make(map[string]*assessment.AppScope, len(plan.Config.Targets))
	for _, target := range plan.Config.Targets {
		if target.Kind == assessment.KindURL || target.Kind == assessment.KindDomain || target.Kind == assessment.KindHost {
			scope := assessment.AppScopeForTarget(plan.Config, target.ID)
			appScopes[target.ID] = &scope
		}
	}
	byName := make(map[string]Runner, len(p.Runners))
	for _, runner := range p.Runners {
		byName[runner.Name()] = runner
	}
	// nmap has a descriptor stub in the legacy recon phase; the typed assessment
	// path dispatches this real adapter instead.
	byName["nmap"] = nmapAssessmentRunner{}
	// Masscan is an assessment-only opt-in runner. Keeping it out of the legacy
	// pipeline prevents empty legacy scanner selections from silently adding raw
	// network probes to existing scans.
	byName["masscan"] = masscanRunner{}
	// Nikto is opt-in and root-path-only; it does not enter legacy runs.
	byName["nikto"] = niktoRunner{}
	// Dalfox is opt-in XSS detection over discovered parameterized URLs.
	byName["dalfox"] = dalfoxRunner{}
	// Wapiti is opt-in bounded web fuzzing seeded with discovered endpoints.
	byName["wapiti"] = wapitiRunner{}
	// kube-bench is opt-in CIS Kubernetes benchmark (read-only).
	byName["kube-bench"] = kubeBenchRunner{}
	// prowler / scoutsuite are opt-in, read-only cloud posture audits.
	byName["prowler"] = prowlerRunner{}
	byName["scoutsuite"] = scoutSuiteRunner{}
	byName["lynis"] = lynisRunner{}
	byName["dnsx"] = dnsxRunner{}
	byName["subfinder"] = subfinderRunner{}
	byName["amass"] = amassRunner{}
	byName["httpx"] = httpxRunner{}
	byName["gau"] = historicalRunner{provider: "gau"}
	byName["waybackurls"] = historicalRunner{provider: "waybackurls"}
	byName["sslyze"] = sslyzeRunner{}
	byName["apichecks"] = apiChecksRunner{}
	byName["apiwrites"] = apiWritesRunner{}
	completed := make(map[string]Run)
	for _, run := range existing {
		if run.Terminal() {
			completed[assessmentJobRunKey(run.Scope, run.Scanner, run.Variant, run.PlanFingerprint)] = run
		}
	}

	surfaces := map[string]*AttackSurface{}
	results := make([]Run, 0, len(plan.Jobs))
	jobOutcomes := make(map[string]Run, len(plan.Jobs))
	var checkpointErr error
	appendOutcome := func(job PlanJob, run Run) {
		run.Stage = job.Stage
		run.AuthContextID, run.AuthIdentity, run.AuthRole = job.AuthContextID, job.AuthIdentity, job.AuthRole
		run.WorkflowVersion = plan.Config.WorkflowVersion
		if surfaces[job.TargetID] == nil && expanded {
			surfaces[job.TargetID] = &AttackSurface{SchemaVersion: AttackSurfaceSchemaVersion, ClassifierVersion: AttackSurfaceClassifierVersion, Scope: scopeForInventoryJob(job), Target: job.Target, Endpoints: []AttackSurfaceEndpoint{}}
		}
		if surface := surfaces[job.TargetID]; surface != nil {
			surface.WorkflowVersion = plan.Config.WorkflowVersion
			MergeRunAssets(surface, run)
			_ = SaveAttackSurface(scanDir, surface)
		}
		results = append(results, run)
		jobOutcomes[job.ID] = run
		if err := saveAssessmentWorkflow(scanDir, plan, results); err != nil {
			checkpointErr = err
			last := &results[len(results)-1]
			last.Status, last.GapKind = "failed", GapInterruptedWrite
			last.Reason = "workflow checkpoint could not be stored: " + err.Error()
			jobOutcomes[job.ID] = *last
		}
	}
	authVerified := make(map[string]bool)
	webDeadlines := map[string]time.Time{}
	repoCheckouts := map[string]repoCheckout{}
	targetKinds := map[string]assessment.TargetKind{}
	targetByID := map[string]assessment.Target{}
	for _, target := range plan.Config.Targets {
		targetKinds[target.ID] = target.Kind
		targetByID[target.ID] = target
	}

	// Web discovery builds one normalized inventory per target. A valid snapshot
	// is reused on resume; if only the raw JSONL remains, it is reparsed without
	// touching the target. The runtime inventory refines scanner inputs but never
	// changes the accepted assessment plan or its fingerprint.
	discoveredAPIs := map[string][]APIEndpoint{}
	pendingHistory := map[string][]HistoricalCandidate{}
	preCrawlRuns := map[string]Run{}
	explicitCrawl := map[string]bool{}
	for _, job := range plan.Jobs {
		if job.Scanner == "katana" {
			explicitCrawl[job.TargetID] = true
		}
	}
	preparedSurfaces := map[string]bool{}
	prepareSurface := func(target assessment.Target) {
		preparedSurfaces[target.ID] = true
		switch target.Kind {
		case assessment.KindURL, assessment.KindDomain, assessment.KindHost:
		default:
			return
		}
		crawlScope := "discovery:" + target.ID
		authBound := assessmentWebAuthBound(plan.Config.Access, target.ID)
		if authBound {
			if err := p.refreshAssessmentWebAuth(ctx, target.ID); err != nil {
				// A requested authenticated crawl must not quietly become a
				// public crawl when a cookie has expired or login failed.
				authVerified[target.ID] = false
			} else {
				authVerified[target.ID] = true
			}
		}
		inventoryScope := assessmentTargetScope(target)
		inventoryTarget := target.Value
		if !strings.HasPrefix(strings.ToLower(inventoryTarget), "http://") && !strings.HasPrefix(strings.ToLower(inventoryTarget), "https://") {
			inventoryTarget = "http://" + inventoryTarget
		}
		crawlReq := Request{
			BrowserEmit: emit, BrowserAttemptControl: p.AttemptControl, ReplayStore: replayStore, ReplayScope: inventoryScope, Target: target.Value, Scope: crawlScope, WorkflowVersion: plan.Config.WorkflowVersion, PlanFingerprint: plan.Fingerprint,
			ScanDir: filepath.Join(scanDir, "discovery", stableJobPath(target.ID)),
			Profile: plan.Config.Profile, TypedAssessment: true,
			TargetAuth: strings.Join(p.Config.AssessmentAuthHeaders[target.ID], "\n"),
			AppScope:   appScopes[target.ID],
		}
		if authBound {
			crawlReq.AuthRefresh = p.Config.AssessmentAuthRefresh[target.ID]
		}
		spec := buildKatana(crawlReq, p.Config)
		surface, valid := LoadAttackSurface(scanDir, inventoryScope, spec.artifact)
		if valid && authBound && !attackSurfaceObservedWithAuth(surface) {
			surface, valid = nil, false
		}
		if !valid && !authBound {
			if parsed, parseErr := ParseKatanaAttackSurfaceScoped(spec.artifact, inventoryScope, inventoryTarget, crawlReq.TargetAuth != "", crawlReq.AppScope); parseErr == nil {
				surface = parsed
			}
		}
		if surface == nil && katanaAvailable(p.Config) && spec.notApp == "" && (!authBound || authVerified[target.ID]) {
			crawlRun := executeSpec(ctx, "katana", crawlReq, p.Config, spec, emit)
			crawlRun.Scope = crawlScope
			crawlRun.Authenticated = authBound && crawlReq.TargetAuth != "" && crawlRun.Status == "completed"
			crawlRun.Stage = StageCrawl
			if crawlRun.Authenticated {
				crawlRun.AuthState, crawlRun.AuthCheckedAt = assessment.StateVerified, time.Now().UTC().Format(time.RFC3339)
				if err := p.refreshAssessmentWebAuth(ctx, target.ID); err != nil {
					crawlRun.Status, crawlRun.Authenticated = "failed", false
					crawlRun.AuthState, crawlRun.GapKind = assessment.StateExpired, GapAuthExpired
					crawlRun.Reason = "authenticated crawl session expired before completion"
					authVerified[target.ID] = false
				}
			}
			if explicitCrawl[target.ID] {
				preCrawlRuns[target.ID] = crawlRun
			} else {
				results = append(results, crawlRun)
			}
			if crawlRun.Status == "completed" {
				surface, _ = ParseKatanaAttackSurfaceScoped(spec.artifact, inventoryScope, inventoryTarget, crawlReq.TargetAuth != "", crawlReq.AppScope)
			}
		} else if surface != nil {
			for _, old := range existing {
				if old.Scanner == "katana" && old.Scope == crawlScope && old.Terminal() {
					if explicitCrawl[target.ID] {
						preCrawlRuns[target.ID] = old
					} else {
						results = append(results, old)
					}
					break
				}
			}
		}
		if surface == nil {
			surface = NewSeedAttackSurface(inventoryScope, inventoryTarget)
		}
		MergeKatanaRedirectTargets(surface, spec.artifact, crawlReq.AppScope, crawlReq.TargetAuth != "")
		if expanded && (!authBound || authVerified[target.ID]) && (p.Config.WebBrowser || authBound || p.Config.AssessmentBrowserStorage[target.ID] != nil) {
			browserReq := crawlReq
			browserReq.BrowserStorage = p.Config.AssessmentBrowserStorage[target.ID]
			browserReq.TargetAuth = strings.Join(p.Config.AssessmentAuthHeaders[target.ID], "\n")
			browserReq.Target = inventoryTarget
			browserReq.ScanDir = filepath.Join(crawlReq.ScanDir, "browser")
			browserRun := DiscoverBrowser(ctx, browserReq, p.Config)
			browserRun.Stage = StageCrawl
			results = append(results, browserRun)
			if parsed, err := ParseKatanaAttackSurfaceScoped(browserRun.ArtifactPath, inventoryScope, inventoryTarget, browserRun.Authenticated, crawlReq.AppScope); err == nil {
				byID := map[string]int{}
				for i := range surface.Endpoints {
					byID[surface.Endpoints[i].ID] = i
				}
				for _, ep := range parsed.Endpoints {
					ep.Provenance = append(ep.Provenance, EndpointProvenance{Tool: "browser", Artifact: browserRun.ArtifactPath, Authenticated: browserRun.Authenticated})
					mergeSurfaceEndpoint(surface, byID, ep)
				}
				surface.RawCount += parsed.RawCount
			} else {
				surface.DiscoveryGaps = append(surface.DiscoveryGaps, "browser discovery produced no usable inventory")
			}
			if browserRun.Completeness == "partial" || browserRun.Status != "completed" {
				surface.DiscoveryGaps = append(surface.DiscoveryGaps, browserRun.Reason)
			}
		}
		if expanded && len(p.Config.AssessmentAuthContexts) > 0 {
			identityReq := crawlReq
			identityReq.Target = inventoryTarget
			results = append(results, discoverAdditionalIdentities(ctx, target.ID, identityReq, p.Config, surface)...)
		}
		surface.WorkflowVersion = plan.Config.WorkflowVersion
		EnsureSeedEndpoint(surface, inventoryTarget)
		var apiEndpoints []APIEndpoint
		for _, endpoint := range plan.APIEndpoints {
			if endpoint.TargetID == target.ID {
				apiEndpoints = append(apiEndpoints, endpoint)
			}
		}
		MergeOpenAPIEndpointsScoped(surface, inventoryTarget, apiEndpoints, appScopes[target.ID])
		if expanded && (!authBound || authVerified[target.ID]) {
			crawlReq.Target = inventoryTarget
			discoveredAPIs[target.ID] = DiscoverAPIs(ctx, crawlReq, p.Config, surface)
			for i := range discoveredAPIs[target.ID] {
				discoveredAPIs[target.ID][i].TargetID = target.ID
			}
			MergeOpenAPIEndpointsScoped(surface, inventoryTarget, discoveredAPIs[target.ID], appScopes[target.ID])
		}
		if expanded {
			addIdentitySchemaSeeds(surface, target.ID, p.Config.AssessmentAuthContexts)
		}
		if expanded && (!authBound || authVerified[target.ID]) && slices.ContainsFunc(plan.Jobs, func(job PlanJob) bool {
			return job.TargetID == target.ID && job.Scanner == "zap" && job.State == PlanSelected
		}) {
			sealInventoryRequests(surface, replayStore, inventoryScope)
			hydrateRequestReplay(surface, replayStore, inventoryScope)
			zapReq := crawlReq
			zapReq.Target = inventoryTarget
			zapReq.TargetAuth = strings.Join(p.Config.AssessmentAuthHeaders[target.ID], "\n")
			results = append(results, runSupplementalZAPDiscovery(ctx, target.ID, zapReq, p.Config, surface, existing, emit, p.AttemptControl)...)
		}
		MergeHistoricalCandidates(surface, pendingHistory[target.ID])
		for _, previous := range results {
			if previous.Scope == inventoryScope || previous.Target == target.Value {
				MergeRunAssets(surface, previous)
			}
		}
		if expanded {
			sealInventoryRequests(surface, replayStore, inventoryScope)
			hydrateRequestReplay(surface, replayStore, inventoryScope)
		}
		surfaces[target.ID] = surface
		_ = SaveAttackSurface(scanDir, surface)
	}

	for jobIndex, job := range plan.Jobs {
		scope := assessmentJobScope(job)
		key := assessmentJobRunKey(scope, job.Scanner, job.Variant, plan.Fingerprint)
		req := Request{
			Target: job.Target, WorkflowVersion: plan.Config.WorkflowVersion,
			ReplayStore: replayStore, ReplayScope: scope,
			Scope: scope,
			ScanDir: filepath.Join(scanDir, "jobs", stableJobPath(job.TargetID), stableJobPath(plan.Fingerprint),
				stableJobPath(job.Scanner+"\x00"+job.Variant)),
			Profile: plan.Config.Profile, TypedAssessment: true,
			AppScope: appScopes[job.TargetID], TestEnvironment: plan.Config.TestEnvironment,
		}
		if checkpointErr != nil {
			run := plannedJobNotRun(job, req, plan.Fingerprint, "workflow checkpoint failed; dependent execution was refused", emit)
			run.GapKind = GapInterruptedWrite
			appendOutcome(job, run)
			continue
		}
		if job.Scanner == "apiwrites" {
			if expanded {
				req.WriteJournalDir = scanDir
			}
			req.APIFixtureDir = p.Config.APIFixtureDir
			for _, endpoint := range plan.APIEndpoints {
				if endpoint.TargetID == job.TargetID {
					req.APIOperationEndpoints = append(req.APIOperationEndpoints, endpoint)
				}
			}
			for _, approval := range plan.Config.WriteApprovals {
				if approval.TargetID == job.TargetID {
					req.WriteApprovals = append(req.WriteApprovals, approval)
				}
			}
		}
		if reason := failedAssessmentDependency(job, jobOutcomes); reason != "" {
			run := plannedJobNotRun(job, req, plan.Fingerprint, reason, emit)
			run.GapKind, run.Stage = GapPrerequisiteFailed, job.Stage
			appendOutcome(job, run)
			continue
		}
		if job.AuthContextID != "" {
			auth, err := p.refreshIdentity(ctx, job.TargetID, job.AuthContextID)
			if err != nil {
				run := plannedJobNotRun(job, req, plan.Fingerprint, "named identity authentication failed; credentials were not substituted", emit)
				run.AuthState, run.GapKind = auth.State, GapAuthFailed
				if run.AuthState == "" {
					run.AuthState = assessment.StateFailed
				}
				appendOutcome(job, run)
				continue
			}
			applyIdentityRequest(&req, auth)
			if job.Scanner == "auth" {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				appendOutcome(job, finalizeRun(Run{Scanner: "auth", Target: job.Target, Scope: scope, Variant: job.Variant, PlanFingerprint: plan.Fingerprint, Status: "completed", StartedAt: now, FinishedAt: now, AuthState: assessment.StateVerified, AuthCheckedAt: now}))
				continue
			}
		}
		if job.Scanner == "auth" {
			if err := p.refreshAssessmentWebAuth(ctx, job.TargetID); err == nil {
				authVerified[job.TargetID] = true
			}
			now := time.Now().UTC().Format(time.RFC3339Nano)
			run := Run{Scanner: "auth", Target: job.Target, Scope: scope, Status: "completed", StartedAt: now, FinishedAt: now, AuthState: assessment.StateVerified, AuthCheckedAt: now, PlanFingerprint: plan.Fingerprint, Variant: job.Variant}
			if !authVerified[job.TargetID] {
				run.Status, run.Reason = "failed", "target-bound authentication could not be verified"
				run.AuthState, run.GapKind = assessment.StateFailed, GapAuthFailed
			}
			appendOutcome(job, run)
			continue
		}
		if job.Scanner == "katana" {
			if job.State != PlanSelected {
				run := plannedJobNotRun(job, req, plan.Fingerprint, "Katana is unavailable in the accepted plan", emit)
				run.GapKind = GapToolUnavailable
				appendOutcome(job, run)
				continue
			}
			if target, found := targetByID[job.TargetID]; found {
				prepareSurface(target)
			}
			run, ok := preCrawlRuns[job.TargetID]
			if !ok {
				run = plannedJobNotRun(job, req, plan.Fingerprint, "Katana did not produce crawl evidence", emit)
				run.GapKind = GapEmptyInput
				if !katanaAvailable(p.Config) {
					run.Reason, run.GapKind = "Katana binary is unavailable", GapToolUnavailable
				}
			}
			run.Scanner, run.Target, run.Scope = job.Scanner, job.Target, scope
			run.PlanFingerprint, run.Variant = plan.Fingerprint, job.Variant
			appendOutcome(job, run)
			continue
		}
		if job.State != PlanSelected && job.State != PlanConditional {
			reason := job.Reason
			if reason == "" {
				reason = "job is not selected by the accepted plan"
			}
			appendOutcome(job, plannedJobNotRun(job, req, plan.Fingerprint, reason, emit))
			continue
		}
		if job.AuthContextID == "" && assessmentWebAuthBound(plan.Config.Access, job.TargetID) && scannerUsesWebAuth(job.Scanner) {
			if err := p.refreshAssessmentWebAuth(ctx, job.TargetID); err != nil {
				run := plannedJobNotRun(job, req, plan.Fingerprint, "authenticated scan skipped: session verification failed", emit)
				run.AuthState, run.GapKind = assessment.StateFailed, GapAuthFailed
				if authVerified[job.TargetID] {
					run.AuthState, run.GapKind = assessment.StateExpired, GapAuthExpired
				}
				run.Stage = job.Stage
				appendOutcome(job, run)
				continue
			}
			authVerified[job.TargetID] = true
		}
		if job.AuthContextID != "" && !preparedSurfaces[job.TargetID] {
			if target, ok := targetByID[job.TargetID]; ok {
				prepareSurface(target)
			}
		}
		surface := surfaces[job.TargetID]
		if surface != nil {
			req.StructuredDispatch = true
		}
		req.APIEndpoints = append(req.APIEndpoints, discoveredAPIs[job.TargetID]...)
		for _, endpoint := range plan.APIEndpoints {
			if endpoint.TargetID == job.TargetID {
				req.APIEndpoints = append(req.APIEndpoints, endpoint)
			}
		}
		if expanded && job.Scanner == "apichecks" {
			req.APIFixtureDir = p.Config.APIFixtureDir
			req.AuthorizationExpectations = plan.Config.AuthorizationExpectations
			for _, auth := range p.Config.AssessmentAuthContexts {
				if auth.TargetID == job.TargetID {
					req.AuthContexts = append(req.AuthContexts, auth)
				}
			}
			req.Inventory = surface
			addAuthorizationRequestVariants(surface, req)
			sealInventoryRequests(surface, replayStore, assessmentTargetScope(targetByID[job.TargetID]))
			hydrateRequestReplay(surface, replayStore, assessmentTargetScope(targetByID[job.TargetID]))
		}
		if old, ok := completed[key]; ok && old.Status == "completed" && (!assessmentWebAuthBound(plan.Config.Access, job.TargetID) || old.Authenticated || !scannerUsesWebAuth(job.Scanner)) && VerifyChecksum(old) == nil {

			req.EndpointTargets = dispatchTargetsWithPolicy(surface, job.Scanner, endpointDispatchLimitForWorkflow(job.Scanner, p.Config.WebMaxEndpoints, expanded), req.AppScope, p.Config.Budget, expanded, req.AuthContextID)
			CompleteEndpointCoverage(surface, job.Scanner, old)
			_ = SaveAttackSurface(scanDir, surface)
			appendOutcome(job, old)
			continue
		}
		if headers := p.Config.AssessmentAuthHeaders[job.TargetID]; job.AuthContextID == "" && len(headers) > 0 && scannerUsesWebAuth(job.Scanner) {
			req.TargetAuth = strings.Join(headers, "\n")
			req.AuthRefresh = p.Config.AssessmentAuthRefresh[job.TargetID]
			req.AuthKind = "HTTP headers"
			for _, binding := range plan.Config.Access {
				if binding.Kind == assessment.AccessFormLogin && slices.Contains(binding.TargetIDs, job.TargetID) {
					req.AuthKind = "form login"
					break
				}
			}
		}
		if job.Scanner == "trivy" {
			switch targetKinds[job.TargetID] {
			case assessment.KindDockerImage:
				req.Artifact = Artifact{Kind: "image", Ref: job.Target}
			case assessment.KindSBOM:
				req.Artifact = Artifact{Kind: "sbom", Ref: job.Target}
			}
		}
		if job.Scanner == "prowler" || job.Scanner == "scoutsuite" {
			cred, ok := p.Config.AssessmentCloudCreds[job.TargetID]
			if !ok || len(cred.Env) == 0 {
				appendOutcome(job, plannedJobNotRun(job, req, plan.Fingerprint, "target-bound cloud credential is unavailable; read-only cloud audit was not run", emit))
				continue
			}
			req.CloudCredential = cred
		}
		if job.Scanner == "vuls" || job.Scanner == "lynis" {
			req.VulsSSHHost = p.Config.AssessmentSSHAliases[job.TargetID]
			if req.VulsSSHHost == "" {
				appendOutcome(job, plannedJobNotRun(job, req, plan.Fingerprint, "target-bound SSH alias is unavailable; credentialed host audit was not run", emit))
				continue
			}
		}
		if job.Scanner == "openvas" {
			if expanded && surface != nil {
				for _, service := range surface.Services {
					if service.Host == hostFromTarget(job.Target) && service.Protocol == "tcp" && service.State == "open" {
						req.NetworkPorts = append(req.NetworkPorts, service.Port)
					}
				}
			}
			if credential, ok := p.Config.AssessmentGVMSSH[job.TargetID]; ok {
				req.GVMSSHCredentialID, req.GVMSSHPort = credential.ID, credential.Port
			} else if p.Config.AssessmentSSHRequested[job.TargetID] {
				appendOutcome(job, plannedJobNotRun(job, req, plan.Fingerprint, "target-bound Greenbone SSH credential is unavailable; credentialed OpenVAS was not run", emit))
				continue
			}
		}
		if parsed, err := url.Parse(job.Target); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			req.ApplicationURL = job.Target
		}

		if job.State == PlanConditional {
			reason := ""
			switch {
			case (job.Scanner == "subfinder" || job.Scanner == "amass") && targetKinds[job.TargetID] == assessment.KindDomain && plan.Config.SubdomainDiscovery:
				// The accepted opt-in is the preparation condition. Results are
				// candidates only and never mutate this plan's approved origins.
			case targetKinds[job.TargetID] == assessment.KindRepository:
				// Source scanners read a local checkout; the run keeps reporting
				// the repository URL so coverage still matches the planned job.
				var dir string
				dir, reason = prepareRepositoryCheckout(ctx, scanDir, job.TargetID, job.Target, p.Config.AssessmentRepoCreds[job.TargetID], repoCheckouts)
				if reason == "" {
					req.Target = dir
				}
			case job.Scanner != "vuls" && job.Scanner != "lynis":
				reason = prepareLocalAssessmentResource(plan.Config.Mode, targetKinds[job.TargetID], job.Target, job.Scanner)
			}
			if reason != "" {
				appendOutcome(job, plannedJobNotRun(job, req, plan.Fingerprint, reason, emit))
				continue
			}
			// The accepted plan remains immutable; this job alone is promoted
			// after its scoped resource passes the runtime check.
		}
		if req.ApplicationURL != "" && p.Config.WebBudget > 0 {
			deadline, exists := webDeadlines[job.TargetID]
			if !exists {
				deadline = time.Now().Add(p.Config.WebBudget)
				webDeadlines[job.TargetID] = deadline
			}
			if !time.Now().Before(deadline) {
				appendOutcome(job, plannedJobNotRun(job, req, plan.Fingerprint, "web profile time budget exhausted; remaining coverage was not tested", emit))
				continue
			}
		}
		runner, ok := byName[job.Scanner]
		if !ok {
			appendOutcome(job, failedPlannedJob(job, req, plan.Fingerprint, "planned scanner has no execution adapter", emit))
			continue
		}
		req.EndpointTargets = dispatchTargetsWithPolicy(surface, job.Scanner, endpointDispatchLimitForWorkflow(job.Scanner, p.Config.WebMaxEndpoints, expanded), req.AppScope, p.Config.Budget, expanded, req.AuthContextID)
		if surface != nil {
			req.EndpointMethods = map[string]string{}
			for _, ep := range surface.Endpoints {
				req.EndpointMethods[ep.URL] = ep.Method
			}
		}
		constrainCredentialTargets(&req, surface, job.Scanner)
		_ = SaveAttackSurface(scanDir, surface)
		if err := ctx.Err(); err != nil {
			run := cancelledRun(job.Scanner, scope, req, err, emit)
			run.Variant, run.AssessmentTypes, run.PlanFingerprint = job.Variant, jobAssessmentTypes(job), plan.Fingerprint
			appendOutcome(job, run)
			continue
		}
		attemptID, err := newAssessmentAttemptID()
		if err != nil {
			appendOutcome(job, failedPlannedJob(job, req, plan.Fingerprint, fmt.Sprintf("create attempt ID: %v", err), emit))
			continue
		}
		req.AttemptID, req.PlanFingerprint = attemptID, plan.Fingerprint
		req.ScanDir = filepath.Join(req.ScanDir, attemptID)
		if err := os.MkdirAll(req.ScanDir, 0o700); err != nil {
			appendOutcome(job, failedPlannedJob(job, req, plan.Fingerprint, fmt.Sprintf("create job artifact directory: %v", err), emit))
			continue
		}
		req.InputRequests = BuildScannerInputs(surface, req, job.Scanner)
		manifestPath, manifestErr := SaveScannerInputs(req, job.Scanner)
		if manifestErr != nil {
			appendOutcome(job, failedPlannedJob(job, req, plan.Fingerprint, "could not persist scanner inputs", emit))
			continue
		}
		jobCtx, jobCancel := context.WithCancel(ctx)
		stageDeadline := time.Time{}
		if req.ApplicationURL != "" && p.Config.WebBudget > 0 {
			deadline := webDeadlines[job.TargetID]
			pending := 1
			for _, later := range plan.Jobs[jobIndex+1:] {
				if later.TargetID != job.TargetID || (later.State != PlanSelected && later.State != PlanConditional) {
					continue
				}
				if old, ok := completed[assessmentJobRunKey(assessmentJobScope(later), later.Scanner, later.Variant, plan.Fingerprint)]; ok && old.Status == "completed" && VerifyChecksum(old) == nil {
					continue
				}
				pending++
			}
			if pending > 1 {
				stageDeadline = time.Now().Add(time.Until(deadline) / time.Duration(pending))
				deadline = stageDeadline
			}
			jobCancel()
			jobCtx, jobCancel = context.WithDeadline(ctx, deadline)
		}
		unregisterAttempt := func() {}
		if p.AttemptControl != nil {
			unregisterAttempt = p.AttemptControl(attemptID, jobCancel)
		}
		runEmit := emit
		if emit != nil {
			runEmit = func(event Event) {
				// The coordinator owns terminal state after cancellation, authentication,
				// gateway evidence, and artifact handling have been reconciled.
				if event.Type == "scanner_completed" || event.Type == "scanner_failed" {
					return
				}
				if event.Run.Scanner != "" {
					event.Run.Target = job.Target
					event.Run.Scope = scope
					event.Run.Variant = job.Variant
					event.Run.AssessmentTypes = jobAssessmentTypes(job)
					event.Run.PlanFingerprint = plan.Fingerprint
					event.Run.AttemptID = attemptID
					event.Run.AuthContextID, event.Run.AuthIdentity, event.Run.AuthRole = job.AuthContextID, job.AuthIdentity, job.AuthRole
				}
				emit(event)
			}
		}
		var gateway *RecordingGateway
		if expanded && req.AppScope != nil && (job.Scanner == "nuclei" || job.Scanner == "wapiti" || job.Scanner == "dalfox") {
			var err error
			gateway, err = NewRecordingGateway(jobCtx, req, p.Config, job.Scanner)
			if err != nil {
				jobCancel()
				unregisterAttempt()
				appendOutcome(job, failedPlannedJob(job, req, plan.Fingerprint, "recording gateway unavailable", emit))
				continue
			}
			req.GatewayURL, req.GatewayCAPath, req.Gateway = gateway.URL, gateway.CAPath, gateway
			req.Secrets = append(req.Secrets, gateway.password)
		}
		run := runAttempt(jobCtx, runner, req, p.Config, runEmit)
		if gateway != nil {
			run.CoverageEventsPath = gateway.EventPath
			if err := gateway.Close(); err != nil {
				run.Status, run.Reason = "failed", "coverage recording failed"
			}
			gateway.ApplyOutcome(&run)
		}

		run.InputManifestPath = manifestPath
		userStopped := jobCtx.Err() == context.Canceled && ctx.Err() == nil
		budgetExpired := jobCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
		jobCancel()
		unregisterAttempt()
		if userStopped {
			run.Status = "cancelled"
			run.ExecutionOutcome, run.Outcome, run.Completeness = "CANCELLED", "PARTIAL", "partial"
			run.Reason = "scanner stopped by user; partial output and artifacts were retained"
			run.FinishedAt = time.Now().Format(time.RFC3339Nano)
		}
		if budgetExpired {
			run.ExecutionOutcome, run.Outcome, run.Completeness = "TIMEOUT", "TIMEOUT", "partial"
			run.Status = "failed"
			if !stageDeadline.IsZero() && time.Now().Before(webDeadlines[job.TargetID]) {
				run.Reason = "scanner stage time budget reached; assessment coverage is partial"
			} else {
				run.Reason = "web profile time budget exhausted; assessment coverage is partial"
			}
		}
		run.Authenticated = req.TargetAuth != "" && run.Status == "completed" && scannerUsesWebAuth(job.Scanner)
		if run.Authenticated && run.AuthState == "" {
			run.AuthState, run.AuthCheckedAt = assessment.StateVerified, time.Now().UTC().Format(time.RFC3339)
		}
		if run.Authenticated && job.Scanner == "nuclei" {
			if err := refreshRunIdentity(ctx, p, job); err != nil {
				run.Status, run.Authenticated = "failed", false
				run.AuthState, run.GapKind = assessment.StateExpired, GapAuthExpired
				run.Reason = "authenticated session expired during Nuclei scan; coverage is partial"
				authVerified[job.TargetID] = false
			}
		}
		run.Stage = job.Stage
		run.Target = job.Target
		run.Scope = scope
		run.WorkflowVersion = plan.Config.WorkflowVersion
		run.Variant = job.Variant
		run.AssessmentTypes = jobAssessmentTypes(job)
		run.PlanFingerprint = plan.Fingerprint
		run.AttemptID = attemptID
		if (job.Scanner == "gau" || job.Scanner == "waybackurls") && run.Status == "completed" {
			if surface == nil {
				pendingHistory[job.TargetID] = append(pendingHistory[job.TargetID], run.HistoricalCandidates...)
			} else {
				MergeHistoricalCandidates(surface, run.HistoricalCandidates)
			}
		}
		run = finalizeRun(run)
		if emit != nil {
			typ := "scanner_completed"
			if run.Status != "completed" {
				typ = "scanner_failed"
			}
			emit(Event{Type: typ, Scanner: job.Scanner, Run: run, Output: run.Reason})
		}
		CompleteEndpointCoverage(surface, job.Scanner, run)
		_ = SaveAttackSurface(scanDir, surface)
		appendOutcome(job, run)
	}
	if err := saveAssessmentWorkflow(scanDir, plan, results); err != nil && len(results) > 0 {
		last := &results[len(results)-1]
		last.Status, last.GapKind = "failed", GapInterruptedWrite
		last.Reason = "workflow manifest could not be stored: " + err.Error()
	}
	return results
}

func assessmentTargetScope(target assessment.Target) string {
	if target.Kind == assessment.KindURL {
		return "app:" + target.ID
	}
	return "host:" + target.ID
}

func assessmentWebAuthBound(bindings []assessment.AccessBinding, targetID string) bool {
	for _, binding := range bindings {
		switch binding.Kind {
		case assessment.AccessApplicationHeaders, assessment.AccessApplicationCookies, assessment.AccessBearerToken, assessment.AccessAPIKey, assessment.AccessFormLogin:
			if slices.Contains(binding.TargetIDs, targetID) {
				return true
			}
		}
	}
	return false
}

func (p *Pipeline) refreshAssessmentWebAuth(ctx context.Context, targetID string) error {
	current := p.Config.AssessmentAuthHeaders[targetID]
	refresh := p.Config.AssessmentAuthRefresh[targetID]
	if len(current) == 0 || refresh == nil {
		return fmt.Errorf("authenticated session is unavailable")
	}
	next, err := refresh(ctx, append([]string(nil), current...))
	if err != nil || len(next) == 0 {
		return fmt.Errorf("authenticated session verification failed")
	}
	p.Config.AssessmentAuthHeaders[targetID] = append([]string(nil), next...)
	return nil
}

func attackSurfaceObservedWithAuth(surface *AttackSurface) bool {
	if surface == nil || surface.SourceChecksum == "" {
		return false
	}
	for _, endpoint := range surface.Endpoints {
		if endpoint.ObservedWithAuth {
			return true
		}
	}
	return false
}

func prepareLocalAssessmentResource(mode assessment.Mode, kind assessment.TargetKind, value, scannerID string) string {
	switch kind {
	case assessment.KindLocalSourcePath:
		if mode != assessment.ModeWhiteBox || !filepath.IsAbs(value) {
			return "White Box local source must be an absolute server path"
		}
		info, err := os.Stat(value)
		if err != nil || !info.IsDir() {
			return "local source directory is unavailable"
		}
		return ""
	case assessment.KindSBOM:
		if scannerID != "trivy" || !filepath.IsAbs(value) {
			return "SBOM requires an absolute server file path and a supported adapter"
		}
		info, err := os.Stat(value)
		if err != nil || !info.Mode().IsRegular() {
			return "SBOM file is unavailable"
		}
		return ""
	case assessment.KindDockerImage:
		pinned, _ := regexp.MatchString(`^[^\s@]+@sha256:[a-fA-F0-9]{64}$`, value)
		if mode != assessment.ModeWhiteBox || scannerID != "trivy" || !pinned {
			return "Trivy image assessment requires a digest-pinned image reference in White Box mode"
		}
		return ""
	default:
		return "conditional job awaits target-scoped preparation"
	}
}

func failedAssessmentJobs(jobs []PlanJob, scanDir, fingerprint, reason string, emit EmitFunc) []Run {
	runs := make([]Run, 0, len(jobs))
	for _, job := range jobs {
		req := Request{Target: job.Target, Scope: assessmentJobScope(job), ScanDir: scanDir}
		runs = append(runs, failedPlannedJob(job, req, fingerprint, reason, emit))
	}
	return runs
}

func assessmentJobScope(job PlanJob) string {
	if parsed, err := url.Parse(job.Target); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
		return "app:" + job.TargetID
	}
	return "host:" + job.TargetID
}

func assessmentJobRunKey(scope, scanner, variant, fingerprint string) string {
	if variant == "" {
		variant = "legacy"
	}
	return scope + "\x00" + scanner + "\x00" + variant + "\x00" + fingerprint
}

func failedAssessmentDependency(job PlanJob, outcomes map[string]Run) string {
	for _, dependency := range job.Dependencies {
		run, ok := outcomes[dependency]
		if !ok || run.Status != "completed" {
			return "prerequisite job " + dependency + " did not complete"
		}
	}
	return ""
}

func jobAssessmentTypes(job PlanJob) []assessment.Type {
	if len(job.AssessmentTypes) > 0 {
		return append([]assessment.Type(nil), job.AssessmentTypes...)
	}
	if job.AssessmentType != "" {
		return []assessment.Type{job.AssessmentType}
	}
	return nil
}

func stableJobPath(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}

func newAssessmentAttemptID() (string, error) {
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes[:]), nil
}

func plannedJobNotRun(job PlanJob, req Request, fingerprint, reason string, emit EmitFunc) Run {
	now := time.Now().Format(time.RFC3339Nano)
	run := Run{Scanner: job.Scanner, Variant: job.Variant, AssessmentTypes: jobAssessmentTypes(job), PlanFingerprint: fingerprint, Scope: req.Scope, Target: req.Target, Status: "skipped", Reason: reason, StartedAt: now, FinishedAt: now}
	if job.Scanner == "zap" && strings.Contains(reason, "auth") {
		base := filepath.Join(req.ScanDir, "scanner-output", "zap")
		if err := os.MkdirAll(base, 0o700); err == nil {
			line := "Authentication failed: " + reason + "\n"
			run.StdoutPath = filepath.Join(base, "stdout.log")
			run.TranscriptPath = filepath.Join(base, "combined.log")
			if os.WriteFile(run.StdoutPath, []byte(line), 0o600) == nil && os.WriteFile(run.TranscriptPath, []byte(line), 0o600) == nil {
				run = finalizeRun(run)
			} else {
				run.StdoutPath, run.TranscriptPath = "", ""
			}
		}
	}
	if emit != nil {
		emit(Event{Type: "scanner_skipped", Scanner: job.Scanner, Run: run, Output: reason})
	}
	return run
}

func failedPlannedJob(job PlanJob, req Request, fingerprint, reason string, emit EmitFunc) Run {
	now := time.Now().Format(time.RFC3339Nano)
	run := Run{Scanner: job.Scanner, Variant: job.Variant, AssessmentTypes: jobAssessmentTypes(job), PlanFingerprint: fingerprint, Scope: req.Scope, Target: req.Target, Status: "failed", Reason: reason, StartedAt: now, FinishedAt: now}
	if emit != nil {
		emit(Event{Type: "scanner_failed", Scanner: job.Scanner, Run: run, Output: reason})
	}
	return run
}

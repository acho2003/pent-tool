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
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// HasAssessmentRunner reports whether a scanner ID has a direct job adapter.
// Legacy recon stubs are intentionally excluded: typed plans must not claim
// that an installed binary can run as an assessment job unless the pipeline
// has a scoped adapter for it.
func HasAssessmentRunner(id string) bool {
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
	byName := make(map[string]Runner, len(p.Runners))
	for _, runner := range p.Runners {
		byName[runner.Name()] = runner
	}
	completed := make(map[string]Run)
	for _, run := range existing {
		if run.Terminal() {
			completed[assessmentJobRunKey(run.Scope, run.Scanner, run.Variant, run.PlanFingerprint)] = run
		}
	}

	results := make([]Run, 0, len(plan.Jobs))
	webDeadlines := map[string]time.Time{}
	for _, job := range plan.Jobs {
		scope := assessmentJobScope(job)
		key := assessmentJobRunKey(scope, job.Scanner, job.Variant, plan.Fingerprint)
		if old, ok := completed[key]; ok && old.Status == "completed" && VerifyChecksum(old) == nil {
			results = append(results, old)
			continue
		}
		req := Request{
			Target: job.Target,
			Scope:  scope,
			ScanDir: filepath.Join(scanDir, "jobs", stableJobPath(job.TargetID), stableJobPath(plan.Fingerprint),
				stableJobPath(job.Scanner+"\x00"+job.Variant)),
			Profile: plan.Config.Profile, TypedAssessment: true,
		}
		if parsed, err := url.Parse(job.Target); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			req.ApplicationURL = job.Target
		}

		if job.State == PlanConditional {
			results = append(results, plannedJobNotRun(job, req, plan.Fingerprint, "conditional job awaits target-scoped preparation", emit))
			continue
		}
		if job.State != PlanSelected {
			results = append(results, plannedJobNotRun(job, req, plan.Fingerprint, "job is not selected by the accepted plan", emit))
			continue
		}
		if req.ApplicationURL != "" && p.Config.WebBudget > 0 {
			deadline, exists := webDeadlines[job.TargetID]
			if !exists {
				deadline = time.Now().Add(p.Config.WebBudget)
				webDeadlines[job.TargetID] = deadline
			}
			if !time.Now().Before(deadline) {
				results = append(results, plannedJobNotRun(job, req, plan.Fingerprint, "web profile time budget exhausted; remaining coverage was not tested", emit))
				continue
			}
		}
		runner, ok := byName[job.Scanner]
		if !ok {
			results = append(results, failedPlannedJob(job, req, plan.Fingerprint, "planned scanner has no execution adapter", emit))
			continue
		}
		if err := ctx.Err(); err != nil {
			run := cancelledRun(job.Scanner, scope, req, err, emit)
			run.Variant, run.AssessmentTypes, run.PlanFingerprint = job.Variant, jobAssessmentTypes(job), plan.Fingerprint
			results = append(results, run)
			continue
		}
		attemptID, err := newAssessmentAttemptID()
		if err != nil {
			results = append(results, failedPlannedJob(job, req, plan.Fingerprint, fmt.Sprintf("create attempt ID: %v", err), emit))
			continue
		}
		req.ScanDir = filepath.Join(req.ScanDir, attemptID)
		if err := os.MkdirAll(req.ScanDir, 0o700); err != nil {
			results = append(results, failedPlannedJob(job, req, plan.Fingerprint, fmt.Sprintf("create job artifact directory: %v", err), emit))
			continue
		}
		jobCtx := ctx
		jobCancel := func() {}
		if req.ApplicationURL != "" && p.Config.WebBudget > 0 {
			jobCtx, jobCancel = context.WithDeadline(ctx, webDeadlines[job.TargetID])
		}
		runEmit := emit
		if emit != nil {
			runEmit = func(event Event) {
				if event.Run.Scanner != "" {
					event.Run.Scope = scope
					event.Run.Variant = job.Variant
					event.Run.AssessmentTypes = jobAssessmentTypes(job)
					event.Run.PlanFingerprint = plan.Fingerprint
					event.Run.AttemptID = attemptID
				}
				emit(event)
			}
		}
		run := runAttempt(jobCtx, runner, req, p.Config, runEmit)
		budgetExpired := jobCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
		jobCancel()
		if budgetExpired {
			run.Reason = "web profile time budget exhausted; assessment coverage is partial"
		}
		run.Scope = scope
		run.Variant = job.Variant
		run.AssessmentTypes = jobAssessmentTypes(job)
		run.PlanFingerprint = plan.Fingerprint
		run.AttemptID = attemptID
		results = append(results, run)
	}
	return results
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

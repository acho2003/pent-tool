package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestAssessmentJobsDoNotCrawlBeforeDNSPrerequisite(t *testing.T) {
	dir := t.TempDir()
	dnsx := filepath.Join(dir, "dnsx")
	katana := filepath.Join(dir, "katana")
	marker := filepath.Join(dir, "crawled")
	if err := os.WriteFile(dnsx, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(katana, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := assessment.Target{ID: "app", Kind: assessment.KindDomain, Value: "app.example.test"}
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Targets: []assessment.Target{target}}, Fingerprint: "sha256:dns-before-crawl", Jobs: []PlanJob{
		{ID: "dns", Scanner: "dnsx", TargetID: target.ID, Target: target.Value, State: PlanSelected, Stage: StageDNS},
		{ID: "crawl", Scanner: "katana", TargetID: target.ID, Target: target.Value, State: PlanSelected, Stage: StageCrawl, Dependencies: []string{"dns"}},
	}}
	p := &Pipeline{Config: Config{DNSXPath: dnsx, KatanaPath: katana}, Runners: []Runner{}}
	runs := p.RunAssessmentJobs(t.Context(), plan, filepath.Join(dir, "scan"), nil, nil)
	if len(runs) != 2 || runs[0].Status != "failed" || runs[1].GapKind != GapPrerequisiteFailed {
		t.Fatalf("prerequisite did not gate crawl: %+v", runs)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Katana was launched before DNS result: %v", err)
	}
}

type assessmentPolicyProbe struct {
	requests []Request
	budgets  []*AssessmentBudget
}

func (*assessmentPolicyProbe) Name() string { return "policy-probe" }
func (p *assessmentPolicyProbe) Descriptor() Descriptor {
	return Descriptor{Name: p.Name(), Phase: PhaseWeb, Tracks: []Track{TrackWeb}}
}
func (p *assessmentPolicyProbe) Run(_ context.Context, req Request, cfg Config, _ EmitFunc) Run {
	p.requests = append(p.requests, req)
	p.budgets = append(p.budgets, cfg.Budget)
	return Run{Scanner: p.Name(), Target: req.Target, Status: "completed"}
}

func TestAssessmentJobsPassScopeAndOneBudgetToAllTargets(t *testing.T) {
	probe := &assessmentPolicyProbe{}
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{
		{ID: "one", Kind: assessment.KindURL, Value: "https://one.example.test/app"},
		{ID: "two", Kind: assessment.KindURL, Value: "https://two.example.test/app"},
	}}
	plan := AssessmentPlan{Config: cfg, Fingerprint: "sha256:scope-budget", Jobs: []PlanJob{
		{ID: "one", Scanner: probe.Name(), TargetID: "one", Target: cfg.Targets[0].Value, State: PlanSelected},
		{ID: "two", Scanner: probe.Name(), TargetID: "two", Target: cfg.Targets[1].Value, State: PlanSelected},
	}}
	p := &Pipeline{Config: Config{KatanaPath: "/nonexistent/katana"}, Runners: []Runner{probe}}
	runs := p.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if len(runs) != 2 || len(probe.requests) != 2 || probe.budgets[0] == nil || probe.budgets[0] != probe.budgets[1] {
		t.Fatalf("assessment jobs did not receive one shared budget: runs=%d requests=%d", len(runs), len(probe.requests))
	}
	for i, req := range probe.requests {
		if req.AppScope == nil {
			t.Fatalf("job %d has no application scope", i)
		}
		if ok, reason := req.AppScope.Allows(cfg.Targets[i].Value + "/child"); !ok {
			t.Errorf("job %d rejects its own child path: %s", i, reason)
		}
		if ok, _ := req.AppScope.Allows(cfg.Targets[1-i].Value); ok {
			t.Errorf("job %d accepts the other application's origin", i)
		}
	}
}

type cancellableAssessmentProbe struct{ started chan struct{} }

func (*cancellableAssessmentProbe) Name() string             { return "cancellable-probe" }
func (p *cancellableAssessmentProbe) Descriptor() Descriptor { return Descriptor{Name: p.Name()} }
func (p *cancellableAssessmentProbe) Run(ctx context.Context, req Request, _ Config, emit EmitFunc) Run {
	close(p.started)
	<-ctx.Done()
	return cancelledRun(p.Name(), "", req, ctx.Err(), emit)
}

func TestAssessmentJobCanCancelIndividualAttempt(t *testing.T) {
	probe := &cancellableAssessmentProbe{started: make(chan struct{})}
	registered := make(chan context.CancelFunc, 1)
	plan := AssessmentPlan{Fingerprint: "sha256:cancel-one", Jobs: []PlanJob{{ID: "job", Scanner: probe.Name(), TargetID: "app", Target: "https://app.example.test/", State: PlanSelected}}}
	p := &Pipeline{Runners: []Runner{probe}, AttemptControl: func(id string, cancel context.CancelFunc) func() {
		if id == "" {
			t.Error("attempt ID is empty")
		}
		registered <- cancel
		return func() {}
	}}
	done := make(chan []Run, 1)
	go func() { done <- p.RunAssessmentJobs(context.Background(), plan, t.TempDir(), nil, nil) }()
	<-probe.started
	(<-registered)()
	runs := <-done
	if len(runs) != 1 || runs[0].Status != "cancelled" || runs[0].Reason != "scanner stopped by user; partial output and artifacts were retained" {
		t.Fatalf("individual stop did not produce a cancelled run: %+v", runs)
	}
}

func TestAssessmentJobsStopAfterPrerequisiteFailure(t *testing.T) {
	probe := &assessmentPolicyProbe{}
	plan := AssessmentPlan{Fingerprint: "sha256:dependencies", Jobs: []PlanJob{
		{ID: "missing-prerequisite", Scanner: "unavailable-stage", TargetID: "app", Target: "https://app.example.test/", State: PlanSelected, Stage: StageReachability},
		{ID: "dependent", Scanner: probe.Name(), TargetID: "app", Target: "https://app.example.test/", State: PlanSelected, Stage: StageTemplates, Dependencies: []string{"missing-prerequisite"}},
	}}
	p := &Pipeline{Runners: []Runner{probe}}
	runs := p.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if len(runs) != 2 || runs[0].Status != "failed" || runs[1].Status != "skipped" || runs[1].GapKind != GapPrerequisiteFailed || len(probe.requests) != 0 {
		t.Fatalf("dependent stage ran after prerequisite failed: runs=%+v calls=%d", runs, len(probe.requests))
	}
}

func TestAssessmentJobsNeverResumeWithInterruptedWrite(t *testing.T) {
	dir := t.TempDir()
	journal, err := OpenWriteJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordIntent(WriteJournalEntry{OperationID: "operation-1", Method: "POST", RedactedURL: "https://app.example.test/fixtures", CleanupRef: "fixture-1"}); err != nil {
		t.Fatal(err)
	}
	probe := &assessmentPolicyProbe{}
	plan := AssessmentPlan{Fingerprint: "sha256:journal", Jobs: []PlanJob{{ID: "next", Scanner: probe.Name(), TargetID: "app", Target: "https://app.example.test/", State: PlanSelected}}}
	runs := (&Pipeline{Runners: []Runner{probe}}).RunAssessmentJobs(t.Context(), plan, dir, nil, nil)
	if len(runs) != 1 || runs[0].GapKind != GapInterruptedWrite || len(probe.requests) != 0 {
		t.Fatalf("interrupted write was replayed or not reported: runs=%+v calls=%d", runs, len(probe.requests))
	}
}

func TestExpandedResumeFindsInterruptedAttemptJournal(t *testing.T) {
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	dir := t.TempDir()
	prior, _ := OpenWriteJournal(filepath.Join(dir, "jobs", "app", "plan", "old-attempt"))
	if err := prior.RecordIntent(WriteJournalEntry{OperationID: "old-write", Method: "POST", RedactedURL: "https://app.test/items"}); err != nil {
		t.Fatal(err)
	}
	probe := &assessmentPolicyProbe{}
	pipeline := &Pipeline{Runners: []Runner{probe}}
	plan := AssessmentPlan{Fingerprint: "accepted", Config: assessment.AssessmentConfig{WorkflowVersion: "unified-v1"}, Jobs: []PlanJob{{ID: "nuclei", TargetID: "app", Target: "https://app.test/", Scanner: probe.Name(), Variant: probe.Name(), State: PlanSelected}}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, dir, nil, nil)
	if len(runs) != 1 || runs[0].GapKind != GapInterruptedWrite || len(probe.requests) != 0 {
		t.Fatalf("legacy attempt resumed: %+v", runs)
	}
}

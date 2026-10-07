package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestDirectEgressLimitationOnlyForUnenforcedAdapters(t *testing.T) {
	for _, name := range []string{"katana", "testssl", "nikto", "nmap", "openvas"} {
		got := withDirectEgressLimitation(nil, name)
		if len(got) != 1 || got[0].Kind != LimitationScopeNotGatewayEnforced || got[0].Reason == "" {
			t.Errorf("%s: limitation = %+v", name, got)
		}
		if again := withDirectEgressLimitation(got, name); len(again) != 1 {
			t.Errorf("%s: limitation duplicated: %+v", name, again)
		}
	}
	// Gateway-routed or natively validated adapters must not carry the limitation.
	for _, name := range []string{"nuclei", "wapiti", "dalfox", "zap", "apichecks", "httpx", "browser"} {
		if got := withDirectEgressLimitation(nil, name); len(got) != 0 {
			t.Errorf("%s must not be marked: %+v", name, got)
		}
	}
	existing := []RunLimitation{{Kind: LimitationHeadlessExcluded, Reason: "x"}}
	if got := withDirectEgressLimitation(existing, "katana"); len(got) != 2 || got[0].Kind != LimitationHeadlessExcluded {
		t.Errorf("existing limitations not preserved: %+v", got)
	}
}

func katanaLimitationPlan(workflow string, target assessment.Target) AssessmentPlan {
	return AssessmentPlan{Fingerprint: "egress-" + workflow, Config: assessment.AssessmentConfig{WorkflowVersion: workflow, Targets: []assessment.Target{target}, Types: []assessment.Type{assessment.TypeWebApplication}},
		Jobs: []PlanJob{{ID: "katana-app", Scanner: "katana", Variant: "katana", TargetID: "app", Target: target.Value, State: PlanSelected, AssessmentType: assessment.TypeWebApplication}}}
}

func TestExpandedKatanaRunRecordsGatewayLimitationLegacyDoesNot(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "katana")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	target := assessment.Target{ID: "app", Kind: assessment.KindURL, Value: "http://127.0.0.1:1/app/"}
	cfg := Config{KatanaPath: bin, WebMaxEndpoints: 10, RateRPS: 10, ScopeGuard: nil}
	run := func(workflow string) Run {
		root := t.TempDir()
		pipeline := Pipeline{Config: cfg}
		runs := pipeline.RunAssessmentJobs(t.Context(), katanaLimitationPlan(workflow, target), root, nil, nil)
		for _, r := range runs {
			if r.Scanner == "katana" {
				return r
			}
		}
		t.Fatalf("no katana run for %q: %+v", workflow, runs)
		return Run{}
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	expanded := run("unified-v1")
	found := false
	for _, l := range expanded.Limitations {
		found = found || l.Kind == LimitationScopeNotGatewayEnforced
	}
	if !found {
		t.Fatalf("expanded katana run (status %s) lacks the gateway limitation: %+v reason=%q", expanded.Status, expanded.Limitations, expanded.Reason)
	}
	for _, l := range run("").Limitations {
		if l.Kind == LimitationScopeNotGatewayEnforced {
			t.Fatalf("legacy workflow must not carry the expanded limitation: %+v", l)
		}
	}
}

func TestOutputWriterRedactsAcrossChunkBoundariesAndAppliesTheFullSanitizer(t *testing.T) {
	var sink strings.Builder
	var seq atomic.Int64
	var emitted []string
	writer := newOutputWriter(&sink, "stdout", "nuclei", 0, []string{"split-secret-value"}, &seq, func(e Event) { emitted = append(emitted, e.Output) })
	// A known secret split across two reads, then a credential no exact match knows.
	_, _ = writer.Write([]byte("matched at split-sec"))
	_, _ = writer.Write([]byte("ret-value done\nAuthorization: Bearer unknown-token-123\nGET /x?access_token=abc&page=2 HTTP/1.1\n"))
	_, _ = writer.Write([]byte("unfinished line with password=hunter2"))
	if strings.Contains(sink.String(), "split-secret-value") || strings.Contains(sink.String(), "unknown-token-123") || strings.Contains(sink.String(), "hunter2") {
		t.Fatalf("a credential reached the stream: %q", sink.String())
	}
	if strings.Contains(sink.String(), "unfinished") {
		t.Fatalf("an unfinished line must be held until it ends: %q", sink.String())
	}
	writer.Flush()
	out := sink.String()
	for _, leaked := range []string{"split-secret-value", "unknown-token-123", "hunter2", "abc&"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("%q survived: %q", leaked, out)
		}
	}
	if !strings.Contains(out, "unfinished line with") || !strings.Contains(out, "page=2") || len(emitted) == 0 {
		t.Fatalf("useful output was lost: %q emitted=%v", out, emitted)
	}
	if strings.Join(emitted, "") != out {
		t.Fatalf("the live events and the saved stream disagree: %q vs %q", strings.Join(emitted, ""), out)
	}
}

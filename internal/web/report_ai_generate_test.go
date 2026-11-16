package web

import (
	"context"
	"strings"
	"testing"
)

type fakeReportGenerator struct {
	gotModel, gotSystem, gotUser string
	out                          string
	err                          error
	called                       bool
}

func (f *fakeReportGenerator) Generate(_ context.Context, model, system, user string, _ int64) (string, error) {
	f.called = true
	f.gotModel, f.gotSystem, f.gotUser = model, system, user
	return f.out, f.err
}

func TestAIReportDisabledByDefault(t *testing.T) {
	t.Setenv("XALGORIX_AI_REPORT", "")
	if aiReportEnabled() {
		t.Fatal("AI report must be off by default")
	}
	gen := &fakeReportGenerator{out: "should not run"}
	if _, err := generateAIReport(context.Background(), gen, reportManifest{}); err != errAIReportDisabled {
		t.Fatalf("expected errAIReportDisabled, got %v", err)
	}
	if gen.called {
		t.Fatal("generator must not be called when disabled (no data leaves the host)")
	}
}

func TestAIReportEnabledCallsGenerator(t *testing.T) {
	t.Setenv("XALGORIX_AI_REPORT", "1")
	t.Setenv("XALGORIX_AI_REPORT_MODEL", "")
	gen := &fakeReportGenerator{out: "# Report\n\nbody"}
	manifest := reportManifest{Mode: "GRAY_BOX"}
	got, err := generateAIReport(context.Background(), gen, manifest)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if got != "# Report\n\nbody" {
		t.Fatalf("unexpected output %q", got)
	}
	if !gen.called {
		t.Fatal("generator should have been called")
	}
	if gen.gotModel != defaultAIReportModel {
		t.Fatalf("model = %q, want default %q", gen.gotModel, defaultAIReportModel)
	}
	if !strings.Contains(gen.gotUser, "GRAY_BOX") {
		t.Fatalf("prompt should carry the manifest data, got: %s", gen.gotUser)
	}
	if !strings.Contains(gen.gotSystem, "Never invent findings") {
		t.Fatalf("system prompt should carry the honesty rules")
	}
}

func TestAIReportModelOverride(t *testing.T) {
	t.Setenv("XALGORIX_AI_REPORT_MODEL", "claude-sonnet-5-5")
	if aiReportModel() != "claude-sonnet-5-5" {
		t.Fatalf("model override not applied: %q", aiReportModel())
	}
	t.Setenv("XALGORIX_AI_REPORT_MODEL", "")
	if aiReportModel() != defaultAIReportModel {
		t.Fatalf("default model = %q", aiReportModel())
	}
}

func TestBuildAIReportPromptSerializesManifest(t *testing.T) {
	prompt, err := buildAIReportPrompt(reportManifest{Mode: "BLACK_BOX", PromptVersion: "scanner-report-v8"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "BLACK_BOX") || !strings.Contains(prompt, "scanner-report-v8") {
		t.Fatalf("prompt missing manifest fields: %s", prompt)
	}
	if !strings.Contains(prompt, "```json") {
		t.Fatalf("prompt should embed the findings as JSON")
	}
}

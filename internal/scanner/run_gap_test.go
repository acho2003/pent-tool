package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestRunGapKindConstantsDistinctFromReason(t *testing.T) {
	kinds := []GapKind{
		GapPrerequisiteFailed, GapToolUnavailable, GapExcluded, GapEmptyInput,
		GapBudgetExhausted, GapAuthFailed, GapAuthExpired, GapCancelled, GapInterruptedWrite,
	}
	seen := map[GapKind]bool{}
	for _, k := range kinds {
		if k == "" {
			t.Fatal("gap kind must not be empty; empty means no gap")
		}
		if strings.ContainsAny(string(k), " ;:") || strings.ToLower(string(k)) != string(k) {
			t.Fatalf("gap kind %q is not a stable machine token", k)
		}
		if seen[k] {
			t.Fatalf("duplicate gap kind %q", k)
		}
		seen[k] = true
	}

	// GapKind is a separate field: a free-text Reason never implies a gap kind,
	// and a gap kind serializes under its own key.
	run := Run{Scanner: "zap", Target: "https://app.example", Status: "skipped", Reason: "tool unavailable: zap not installed"}
	if run.GapKind != "" {
		t.Fatal("zero run has a gap kind")
	}
	run.GapKind = GapToolUnavailable
	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["gap_kind"] != string(GapToolUnavailable) || decoded["reason"] != run.Reason {
		t.Fatalf("gap kind and reason not serialized independently: %s", raw)
	}
	var back Run
	if err := json.Unmarshal(raw, &back); err != nil || back.GapKind != GapToolUnavailable {
		t.Fatalf("gap kind did not round-trip: %#v, %v", back, err)
	}
}

func TestRunAuthStateAndLimitationsOmitEmptyForLegacyJSON(t *testing.T) {
	legacy := `{"scanner":"nuclei","authenticated":true,"variant":"authenticated","assessment_types":["WEB_APPLICATION"],"plan_fingerprint":"abc","attempt_id":"a1","scope":"https://app.example","target":"https://app.example","status":"completed","started_at":"2026-10-01T00:00:00Z","finished_at":"2026-10-01T00:05:00Z","exit_code":1,"reason":"partial","stdout_path":"out","stderr_path":"err","transcript_path":"t","artifact_path":"a","checksum":"c","truncated":true,"progress":40,"progress_stage":"spider"}`
	var run Run
	if err := json.Unmarshal([]byte(legacy), &run); err != nil {
		t.Fatal(err)
	}
	if run.GapKind != "" || run.Stage != "" || run.AuthState != "" || run.AuthCheckedAt != "" || run.Limitations != nil {
		t.Fatalf("legacy run decoded new fields: %#v", run)
	}
	out, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != legacy {
		t.Fatalf("legacy run JSON changed:\n got %s\nwant %s", out, legacy)
	}

	run.Stage = "active"
	run.AuthState = assessment.StateExpired
	run.AuthCheckedAt = "2026-10-01T00:04:00Z"
	run.Limitations = []RunLimitation{{Kind: LimitationHeadlessExcluded, Reason: "headless templates require a browser"}}
	out, err = json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"stage":"active"`, `"auth_state":"expired"`, `"auth_checked_at":"2026-10-01T00:04:00Z"`, `"limitations":[{"kind":"headless_excluded","reason":"headless templates require a browser"}]`} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
}

func TestRequestAndConfigRuntimeFieldsAreNotSerialized(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.example", Port: 443, PathPrefix: "/"}})
	req := Request{Target: "https://app.example", AppScope: &scope, TestEnvironment: true}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "app_scope") || strings.Contains(string(raw), "AppScope") || strings.Contains(string(raw), "TestEnvironment") {
		t.Fatalf("runtime request fields serialized: %s", raw)
	}
	if ok, _ := req.AppScope.Allows("https://app.example/login"); !ok {
		t.Fatal("request scope does not authorize its own origin")
	}

	cfg := Config{
		ScopeGuard: func(string, []string) (bool, string) { return true, "self listener" },
		Budget:     NewAssessmentBudget(2, 500, 0),
	}
	if blocked, reason := cfg.ScopeGuard("http://127.0.0.1:8080", nil); !blocked || reason == "" {
		t.Fatal("scope guard hook not callable")
	}
	if _, err := json.Marshal(cfg); err != nil {
		t.Fatalf("config with runtime hooks must still marshal: %v", err)
	}
}

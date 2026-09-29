package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScorecardCountsDetectionsGapsAndFixedCounterpart(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	manifest := labManifest{SchemaVersion: 1, Applications: []labApplication{
		{ID: "vulnerable", BaseURL: "http://127.0.0.1:18080", ExpectedEndpoints: []string{"/", "/search", "/items"}, ExpectedFindings: []findingLabel{{Class: "reflected_xss", Path: "/search"}, {Class: "sql_injection", Path: "/items"}}},
		{ID: "fixed", BaseURL: "http://127.0.0.1:18081", ExpectedEndpoints: []string{"/search"}},
	}}
	observations := observationManifest{SchemaVersion: 1, Runs: []observedRun{
		{ApplicationID: "vulnerable", ResultPath: write("vulnerable.json", scanResult{State: "complete", Findings: []observedFinding{{Title: "Reflected XSS", Endpoint: "http://127.0.0.1:18080/search"}, {Title: "Reflected XSS", Endpoint: "http://127.0.0.1:18080/search"}}}), MetricsPath: write("vulnerable-metrics.json", labMetrics{Requests: 4, Paths: map[string]int{"/": 1, "/search": 2}}), DurationMS: 1000, PeakMemoryBytes: 1000},
		{ApplicationID: "fixed", ResultPath: write("fixed.json", scanResult{State: "complete", Findings: []observedFinding{{Title: "Reflected XSS", Endpoint: "http://127.0.0.1:18081/search"}}}), MetricsPath: write("fixed-metrics.json", labMetrics{Requests: 1, Paths: map[string]int{"/search": 1}}), DurationMS: 1000, PeakMemoryBytes: 1000},
	}}
	got, err := evaluate(manifest, observations, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.TP != 1 || got.FP != 2 || got.FN != 1 || got.EndpointsFound != 3 || got.EndpointsExpected != 4 || got.GatePassed {
		t.Fatalf("incorrect scorecard: %+v", got)
	}
	if got.Classes["reflected_xss"].FP != 2 || got.Classes["sql_injection"].FN != 1 {
		t.Fatalf("per-class score is incorrect: %+v", got.Classes)
	}
	if got.Applications[0].State != "unknown" {
		t.Fatalf("CLI completion was mistaken for assessment coverage: %+v", got.Applications[0])
	}
}

func TestScorecardRequiresEveryApplicationAndComparableCoverage(t *testing.T) {
	manifest := labManifest{SchemaVersion: 1, Applications: []labApplication{{ID: "vulnerable", BaseURL: "http://127.0.0.1:18080", ExpectedEndpoints: []string{"/"}}}}
	if _, err := evaluate(manifest, observationManifest{SchemaVersion: 1}, t.TempDir()); err == nil {
		t.Fatal("missing application result was accepted")
	}
	if path := findingPath("http://127.0.0.1:18080", observedFinding{Endpoint: "http://127.0.0.1:18081/search"}); path != "" {
		t.Fatalf("cross-port finding was assigned to the wrong application: %q", path)
	}
	if !hasCWE("CWE-79, CWE-89", "79") || hasCWE("CWE-179", "79") {
		t.Fatal("CWE matching conflated separate identifiers")
	}
}

func TestScorecardGatePassesOnlyFullyMeasuredLabeledRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	manifest := labManifest{SchemaVersion: 1, Applications: []labApplication{{ID: "vulnerable", BaseURL: "http://127.0.0.1:18080", ExpectedEndpoints: []string{"/search"}, ExpectedFindings: []findingLabel{{Class: "reflected_xss", Path: "/search", Severity: "high"}}}}}
	observations := observationManifest{SchemaVersion: 1, Runs: []observedRun{{
		ApplicationID: "vulnerable", ResultPath: write("result.json", scanResult{Assessment: &scanCoverageState{State: "complete"}, Findings: []observedFinding{{CWE: "CWE-79", Endpoint: "http://127.0.0.1:18080/search"}}}),
		MetricsPath: write("metrics.json", labMetrics{Requests: 1, Paths: map[string]int{"/search": 1}}), DurationMS: 1000, PeakMemoryBytes: 1000,
	}}}
	got, err := evaluate(manifest, observations, dir)
	if err != nil || !got.GatePassed || got.Precision != 1 || got.Recall != 1 || got.TP != 1 {
		t.Fatalf("complete measured run did not pass: %+v err=%v", got, err)
	}
	observations.Runs[0].PeakMemoryBytes = 0
	got, err = evaluate(manifest, observations, dir)
	if err != nil || got.GatePassed {
		t.Fatalf("missing memory measurement passed: %+v err=%v", got, err)
	}
}

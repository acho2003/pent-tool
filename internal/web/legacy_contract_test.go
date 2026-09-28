package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// These tests pin the CURRENT (pre-assessment) on-disk contracts for scan
// records, schedules, and queue state. They are the regression safety net for
// the assessment-modes work: schema v3 and the v1/v2 read adapters (plan
// commit 5) must keep decoding these fixtures with the same field semantics.
// If a change here forces a fixture edit, that is a deliberate contract change
// and must be reviewed as one.

func readLegacyFixture(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "legacy", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}

func TestLegacyContract_ScanRecordV2Decodes(t *testing.T) {
	var rec ScanRecord
	readLegacyFixture(t, "scan_record_v2.json", &rec)

	if rec.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", rec.SchemaVersion)
	}
	if rec.ID != "scan-abc123" || rec.Target != "example.com" {
		t.Errorf("identity fields lost: %+v", rec)
	}
	if rec.ScanMode != "single" || rec.Status != "finished" {
		t.Errorf("mode/status lost: mode=%q status=%q", rec.ScanMode, rec.Status)
	}
	if want := []string{"nuclei", "zap", "testssl"}; !reflect.DeepEqual(rec.Scanners, want) {
		t.Errorf("Scanners = %v, want %v", rec.Scanners, want)
	}
	if want := []string{"critical", "high"}; !reflect.DeepEqual(rec.SeverityFilter, want) {
		t.Errorf("SeverityFilter = %v, want %v", rec.SeverityFilter, want)
	}
	if len(rec.Vulns) != 1 || rec.Vulns[0].Title != "TLS 1.0 enabled" {
		t.Errorf("vulns not preserved: %+v", rec.Vulns)
	}
	if len(rec.ScannerRuns) != 1 || rec.ScannerRuns[0].Scanner != "testssl" {
		t.Errorf("scanner_runs not preserved: %+v", rec.ScannerRuns)
	}
	if rec.ReportMode != "deterministic_fallback" {
		t.Errorf("ReportMode = %q, want deterministic_fallback", rec.ReportMode)
	}
}

// A v1-style record (no schema_version, minimal fields) must decode without
// error and MUST NOT be silently assigned a modern schema version — the
// migration layer, not the raw decode, decides how to treat it.
func TestLegacyContract_ScanRecordV1DecodesAsUnversioned(t *testing.T) {
	var rec ScanRecord
	readLegacyFixture(t, "scan_record_v1.json", &rec)

	if rec.SchemaVersion != 0 {
		t.Errorf("legacy record got SchemaVersion %d, want 0 (unversioned)", rec.SchemaVersion)
	}
	if rec.ID != "scan-legacy-1" || rec.ScanMode != "wildcard" || rec.Status != "completed" {
		t.Errorf("legacy fields lost: %+v", rec)
	}
}

func TestLegacyContract_ScheduleRoundTrips(t *testing.T) {
	var sch ScanSchedule
	readLegacyFixture(t, "schedule.json", &sch)

	if sch.ID != "sched-1" || sch.Interval != "daily" || sch.RunAt != "02:30" {
		t.Errorf("schedule timing lost: %+v", sch)
	}
	if sch.Timezone != "America/Argentina/Buenos_Aires" {
		t.Errorf("timezone lost: %q", sch.Timezone)
	}
	if !sch.Enabled || len(sch.Targets) != 2 || sch.ScanMode != "single" {
		t.Errorf("schedule fields lost: %+v", sch)
	}

	// Re-encode and decode again: the wire-visible fields must survive a full
	// round trip unchanged.
	out, err := json.Marshal(sch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back ScanSchedule
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if !reflect.DeepEqual(sch, back) {
		t.Errorf("schedule not stable across round trip:\n first=%+v\n back =%+v", sch, back)
	}
}

func TestLegacyContract_QueueStateResumeFieldsPreserved(t *testing.T) {
	var qs QueueState
	readLegacyFixture(t, "queue_state.json", &qs)

	if qs.InstanceID != "inst-queue-1" || qs.ScanMode != "wildcard" {
		t.Errorf("queue identity/mode lost: %+v", qs)
	}
	if qs.CurrentIdx != 1 || len(qs.Targets) != 2 {
		t.Errorf("queue progress lost: idx=%d targets=%v", qs.CurrentIdx, qs.Targets)
	}
	if !qs.WildcardDiscoveryDone || qs.WildcardSubIndex != 1 || len(qs.WildcardSubdomains) != 2 {
		t.Errorf("wildcard resume fields lost: %+v", qs)
	}
	if qs.ActiveTarget != "b.example.com" {
		t.Errorf("active target lost: %q", qs.ActiveTarget)
	}
}

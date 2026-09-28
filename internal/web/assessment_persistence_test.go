package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func sampleAssessmentConfig() *assessment.AssessmentConfig {
	return &assessment.AssessmentConfig{
		Mode:    assessment.ModeGrayBox,
		Types:   []assessment.Type{assessment.TypeWebApplication, assessment.TypeAPI},
		Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://example.test/CaseSensitive"}},
		Access:  []assessment.AccessBinding{{TargetIDs: []string{"app"}, Kind: assessment.AccessApplicationHeaders, CredentialID: "cred-ref"}},
		Profile: "web-gentle",
	}
}

func TestAssessmentConfigSurvivesQueueRecovery(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	want := sampleAssessmentConfig()
	s.saveQueueState(0, ScanRequest{InstanceID: "assessment-1", Targets: []string{"https://example.test/CaseSensitive"}, Assessment: want})

	path := s.queueStatePathForInstance("assessment-1")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted QueueState
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	got := scanRequestFromQueueState(&persisted, path).Assessment
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recovered assessment = %#v, want %#v", got, want)
	}
}

func TestAssessmentConfigSurvivesScheduleAndRecordPersistence(t *testing.T) {
	dir := t.TempDir()
	s := &Server{dataDir: dir, schedules: map[string]*ScanSchedule{}}
	want := sampleAssessmentConfig()
	if err := s.saveScheduleToDisk(&ScanSchedule{ID: "schedule-1", Name: "weekly", Assessment: want}); err != nil {
		t.Fatal(err)
	}
	s.loadSchedulesFromDisk()
	if got := s.schedules["schedule-1"].Assessment; !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded schedule assessment = %#v, want %#v", got, want)
	}

	scanDir := filepath.Join(dir, "scan")
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		t.Fatal(err)
	}
	s.saveScanRecordTo(&ScanRecord{SchemaVersion: 3, ID: "scan-1", Assessment: want}, scanDir)
	got, ok := loadScanRecordFromDir(scanDir)
	if !ok || got.SchemaVersion != 3 || !reflect.DeepEqual(got.Assessment, want) {
		t.Fatalf("loaded record = %#v, ok=%v", got, ok)
	}
}

package web

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCalculateNextRun(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		interval string
		want     time.Time
	}{
		{"hourly", now.Add(time.Hour)},
		{"daily", now.AddDate(0, 0, 1)},
		{"weekly", now.AddDate(0, 0, 7)},
		{"monthly", now.AddDate(0, 1, 0)},
		{"unknown", now.AddDate(0, 0, 1)}, // fallback to daily
	}

	for _, tc := range cases {
		t.Run(tc.interval, func(t *testing.T) {
			got := calculateNextRun(tc.interval, now)
			if !got.Equal(tc.want) {
				t.Errorf("calculateNextRun(%q) = %v, want %v", tc.interval, got, tc.want)
			}
		})
	}
}

func TestSchedulesDiskIO(t *testing.T) {
	s := newTestServer(t, nil)

	sch := &ScanSchedule{
		ID:       "test-sch-1",
		Name:     "Test Daily Scan",
		Interval: "daily",
		Enabled:  true,
		Targets:  []string{"localhost"},
	}

	// Test saving
	err := s.saveScheduleToDisk(sch)
	if err != nil {
		t.Fatalf("saveScheduleToDisk failed: %v", err)
	}

	// Verify file is created
	filePath := filepath.Join(s.dataDir, "_schedules", sch.ID+".json")
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("schedule file not created: %v", err)
	}

	// Test loading
	// First clear memory map
	s.schedulesMu.Lock()
	s.schedules = make(map[string]*ScanSchedule)
	s.schedulesMu.Unlock()

	s.loadSchedulesFromDisk()

	s.schedulesMu.RLock()
	loaded, ok := s.schedules[sch.ID]
	s.schedulesMu.RUnlock()

	if !ok {
		t.Fatalf("schedule not found in memory after loading from disk")
	}
	if loaded.Name != sch.Name || loaded.Interval != sch.Interval {
		t.Errorf("loaded schedule mismatch: %+v", loaded)
	}

	// Test deleting
	err = s.deleteScheduleFromDisk(sch.ID)
	if err != nil {
		t.Fatalf("deleteScheduleFromDisk failed: %v", err)
	}

	// Verify file is gone
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("schedule file still exists after deletion")
	}
}

func TestCheckAndRunSchedules(t *testing.T) {
	s := newTestServer(t, nil)

	// Create an enabled schedule whose NextRun is in the past
	dueSch := &ScanSchedule{
		ID:       "due-1",
		Name:     "Due Daily Scan",
		Interval: "daily",
		Enabled:  true,
		NextRun:  time.Now().Add(-10 * time.Minute),
		Targets:  []string{"localhost"},
	}

	// Create an enabled schedule whose NextRun is in the future
	futureSch := &ScanSchedule{
		ID:       "future-1",
		Name:     "Future Daily Scan",
		Interval: "daily",
		Enabled:  true,
		NextRun:  time.Now().Add(10 * time.Minute),
		Targets:  []string{"localhost"},
	}

	// Create a disabled schedule whose NextRun is in the past
	disabledSch := &ScanSchedule{
		ID:       "disabled-1",
		Name:     "Disabled Daily Scan",
		Interval: "daily",
		Enabled:  false,
		NextRun:  time.Now().Add(-10 * time.Minute),
		Targets:  []string{"localhost"},
	}

	s.schedulesMu.Lock()
	s.schedules[dueSch.ID] = dueSch
	s.schedules[futureSch.ID] = futureSch
	s.schedules[disabledSch.ID] = disabledSch
	s.schedulesMu.Unlock()

	// Clear any historical instances loaded on startup
	s.instancesMu.Lock()
	s.instances = make(map[string]*ScanInstance)
	s.instancesMu.Unlock()

	// Call checkAndRunSchedules
	s.checkAndRunSchedules()

	s.schedulesMu.RLock()
	// Check dueSch: should have run, so LastRun should be updated and NextRun pushed forward
	if dueSch.LastRun.IsZero() {
		t.Errorf("due schedule did not run (LastRun is zero)")
	}
	if !dueSch.NextRun.After(time.Now()) {
		t.Errorf("due schedule NextRun not updated correctly: %v", dueSch.NextRun)
	}

	// Check futureSch: should not have run, LastRun should be zero, NextRun remains unchanged
	if !futureSch.LastRun.IsZero() {
		t.Errorf("future schedule ran unexpectedly")
	}

	// Check disabledSch: should not have run, LastRun should be zero
	if !disabledSch.LastRun.IsZero() {
		t.Errorf("disabled schedule ran unexpectedly")
	}
	s.schedulesMu.RUnlock()

	// Wait briefly to let the goroutine register the scan instance
	time.Sleep(100 * time.Millisecond)

	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()

	// Check that we have exactly one instance registered (from the due schedule)
	if len(s.instances) != 1 {
		t.Errorf("expected 1 registered scan instance, got %d", len(s.instances))
	}
}

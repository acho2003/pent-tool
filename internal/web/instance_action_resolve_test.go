package web

import "testing"

// The per-instance action endpoints (stop/pause/restart/start) must resolve not
// just the live instance id but also a scan RECORD id / short alias, because the
// scan-detail page routes by those. Previously a record id 404'd, so Stop/Delete
// did nothing on the scan-detail page while working on the Instances page.
func TestResolveInstanceForAction(t *testing.T) {
	s := newTestServer(t, nil)

	// Live instance keyed by its instance id.
	s.instancesMu.Lock()
	s.instances["inst-xyz"] = &ScanInstance{ID: "inst-xyz", Targets: "att.com", Status: "running"}
	s.instancesMu.Unlock()

	// A persisted scan record whose directory-slug ID differs from the instance
	// id but points back to it via InstanceID (the wildcard-parent shape).
	writeScanRecord(t, s.dataDir, "att.com/2026-07-20/att.com_slug", ScanRecord{
		ID:         "att.com_slug",
		InstanceID: "inst-xyz",
		Target:     "att.com",
		StartedAt:  "2026-07-20T10:00:00Z",
		Status:     "running",
	})

	t.Run("exact instance id", func(t *testing.T) {
		inst, ok := s.resolveInstanceForAction("inst-xyz")
		if !ok || inst == nil || inst.ID != "inst-xyz" {
			t.Fatalf("exact id did not resolve: ok=%v inst=%#v", ok, inst)
		}
	})

	t.Run("scan record id resolves to instance", func(t *testing.T) {
		inst, ok := s.resolveInstanceForAction("att.com_slug")
		if !ok || inst == nil || inst.ID != "inst-xyz" {
			t.Fatalf("record id did not resolve to instance: ok=%v inst=%#v", ok, inst)
		}
	})

	t.Run("unknown id", func(t *testing.T) {
		if _, ok := s.resolveInstanceForAction("does-not-exist"); ok {
			t.Fatal("unknown id should not resolve")
		}
	})

	t.Run("empty id", func(t *testing.T) {
		if _, ok := s.resolveInstanceForAction(""); ok {
			t.Fatal("empty id should not resolve")
		}
	})
}

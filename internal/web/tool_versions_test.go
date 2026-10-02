package web

import (
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/config"
)

const testContentManifest = `{
  "schema_version": 1,
  "lock": {"nuclei_templates_revision": "8b9d065c", "required": {"nuclei": "v3.11.1", "osv-scanner": "v1.9.2", "testssl.sh": "5b90"}, "optional": {"scout": "5.14.0"}},
  "tools": {
    "nuclei": {"pinned": "v3.11.1", "available": true, "version_output": ["Nuclei Engine Version: v3.11.1"]},
    "osv-scanner": {"pinned": "v1.9.2", "available": true, "version_output": ["osv-scanner version: 1.9.2", "commit: n/a"]},
    "testssl.sh": {"pinned": "5b90", "available": true, "version_output": ["testssl.sh 3.3dev"]},
    "scout": {"pinned": "5.14.0", "available": false, "version_output": null}
  }
}`

func TestToolVersionsReadFromContentManifestNeverExec(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "content-manifest.json")
	if err := os.WriteFile(manifest, []byte(testContentManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_CONTENT_MANIFEST", manifest)
	if got := contentManifestPath(); got != manifest {
		t.Fatalf("contentManifestPath() = %q, want override %q", got, manifest)
	}
	want := map[string]string{
		"nuclei":           "Nuclei Engine Version: v3.11.1",
		"osv":              "osv-scanner version: 1.9.2\ncommit: n/a",
		"testssl":          "testssl.sh 3.3dev",
		"scoutsuite":       "unavailable (pinned 5.14.0)",
		"nuclei-templates": "8b9d065c",
	}
	if got := loadToolVersions(manifest); !maps.Equal(got, want) {
		t.Fatalf("loadToolVersions() = %v, want %v", got, want)
	}

	// A scanner binary that records any execution. Server start, preview and
	// fingerprinting may look it up on PATH but must never run it.
	marker := filepath.Join(dir, "executed")
	fake := filepath.Join(dir, "nuclei")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch "+marker+"\necho v9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, &config.Config{NucleiPath: fake, TestsslPath: fake, HttpxPath: fake, KatanaPath: fake})
	if !maps.Equal(s.toolVersions, want) {
		t.Fatalf("server start did not cache manifest versions: %v", s.toolVersions)
	}
	cfg := assessment.AssessmentConfig{Mode: assessment.ModeBlackBox, Types: []assessment.Type{assessment.TypeWebApplication}, Profile: "web-gentle", Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.example.test/"}}}
	first := s.buildAssessmentPlan(cfg).Fingerprint
	if err := os.WriteFile(manifest, []byte(`{"schema_version":1,"tools":{"nuclei":{"available":true,"version_output":["v10"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if second := s.buildAssessmentPlan(cfg).Fingerprint; second != first {
		t.Fatal("tool versions must be read once at server start, not per preview")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a scanner binary was executed to read versions (marker err=%v)", err)
	}

	// Dev builds have no manifest: the map is empty and stable.
	for _, path := range []string{filepath.Join(dir, "missing.json"), fake} {
		if got := loadToolVersions(path); got == nil || len(got) != 0 {
			t.Fatalf("loadToolVersions(%s) = %v, want empty map", path, got)
		}
	}
}

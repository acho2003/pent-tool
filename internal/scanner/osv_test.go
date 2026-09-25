package scanner

import (
	"testing"
	"time"
)

func TestBuildOSVCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildOSV(req, Config{OsvPath: "osv-scanner", OsvTimeout: time.Minute})
	if spec.path != "osv-scanner" {
		t.Fatalf("path %q", spec.path)
	}
	if spec.okExit == nil || !spec.okExit[1] {
		t.Errorf("osv must treat exit 1 (vulns found) as success: %+v", spec.okExit)
	}
}

func TestBuildOSVNoSource(t *testing.T) {
	spec := buildOSV(Request{ScanDir: t.TempDir()}, Config{OsvPath: "osv-scanner", OsvTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp, got %+v", spec)
	}
}

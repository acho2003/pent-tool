package scanner

import (
	"testing"
	"time"
)

func TestBuildGitleaksCommand(t *testing.T) {
	req := Request{Target: "/src/app", ScanDir: t.TempDir()}
	spec := buildGitleaks(req, Config{GitleaksPath: "gitleaks", GitleaksTimeout: time.Minute})
	if spec.path != "gitleaks" {
		t.Fatalf("path %q", spec.path)
	}
	if spec.okExit == nil || !spec.okExit[1] {
		t.Errorf("gitleaks must treat exit 1 (leaks found) as success: %+v", spec.okExit)
	}
}

func TestBuildGitleaksNoSource(t *testing.T) {
	spec := buildGitleaks(Request{ScanDir: t.TempDir()}, Config{GitleaksPath: "gitleaks", GitleaksTimeout: time.Minute})
	if spec.notApp == "" {
		t.Fatalf("expected notApp, got %+v", spec)
	}
}

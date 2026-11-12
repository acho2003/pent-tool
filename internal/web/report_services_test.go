package web

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func servicesReportPlan() *scanner.AssessmentPlan {
	return &scanner.AssessmentPlan{
		Config: assessment.AssessmentConfig{
			Targets: []assessment.Target{
				{ID: "svc-1-url-1", Kind: assessment.KindURL, Value: "http://172.30.3.142:30862"},
				{ID: "svc-1-image", Kind: assessment.KindDockerImage, Value: "hub.example.test/bcrs/auth:6"},
				{ID: "svc-2-url-1", Kind: assessment.KindURL, Value: "http://172.30.3.10:31132"},
				{ID: "loose", Kind: assessment.KindURL, Value: "https://portal.example.test"},
			},
			Services: []assessment.Service{
				{ID: "svc-1", Name: "Auth Service", TargetIDs: []string{"svc-1-url-1", "svc-1-image"}},
				{ID: "svc-2", Name: "Common Service", TargetIDs: []string{"svc-2-url-1"}},
			},
		},
		Capabilities: []assessment.CapabilityEvidence{
			{Capability: assessment.CapAuthWeb, TargetID: "svc-1-url-1", AccessKind: assessment.AccessTokenLogin, State: assessment.StateVerified},
			{Capability: assessment.CapAuthWeb, TargetID: "svc-2-url-1", AccessKind: assessment.AccessTokenLogin, State: assessment.StateAvailable},
		},
	}
}

func TestBuildReportServicesAttributesFindingsRunsAndAuth(t *testing.T) {
	plan := servicesReportPlan()
	runs := []scanner.Run{
		{Scanner: "zap", Scope: "app:svc-1-url-1", Status: "completed"},
		{Scanner: "trivy", Scope: "host:svc-1-image", Status: "completed"},
		{Scanner: "nuclei", Scope: "app:svc-1-url-1", Status: "failed"},
		{Scanner: "zap", Scope: "app:svc-2-url-1", Status: "skipped"},
		{Scanner: "auth", Scope: "app:svc-2-url-1", Status: "completed"},
		{Scanner: "zap", Scope: "app:loose", Status: "completed"},
	}
	vulns := []VulnSummary{
		{Title: "SQL Injection", Severity: "high", Scope: "app:svc-2-url-1"},
		{Title: "CVE in base image", Severity: "critical", Scope: "host:svc-1-image"},
		{Title: "CVE in base image 2", Severity: "High", Scope: "host:svc-1-image"},
		{Title: "Missing CSP", Severity: "informational", Scope: "app:loose"},
		{Title: "Unscoped", Severity: "low", Scope: ""},
	}
	services := buildReportServices(plan, runs, vulns)
	if len(services) != 3 {
		t.Fatalf("expected 2 services + Other targets, got %+v", services)
	}
	auth, common, other := services[0], services[1], services[2]
	if auth.Name != "Auth Service" || auth.Findings != 2 || auth.Counts["critical"] != 1 || auth.Counts["high"] != 1 || len(auth.Targets) != 2 {
		t.Fatalf("auth service row: %+v", auth)
	}
	if auth.Completed != 2 || auth.Failed != 1 || auth.Skipped != 0 || auth.Auth != "verified" {
		t.Fatalf("auth service runs/auth: %+v", auth)
	}
	if common.Findings != 1 || common.Counts["high"] != 1 || common.Skipped != 1 || common.Completed != 0 || common.Auth != "token applied, not verified" {
		t.Fatalf("common service row: %+v", common)
	}
	if other.Name != otherTargetsService || other.Findings != 2 || other.Counts["info"] != 1 || other.Counts["low"] != 1 || other.Completed != 1 {
		t.Fatalf("other targets row: %+v", other)
	}
}

func TestBuildReportServicesLegacyAndNoServices(t *testing.T) {
	if buildReportServices(nil, nil, nil) != nil {
		t.Fatal("legacy record produced services")
	}
	plan := servicesReportPlan()
	plan.Config.Services = nil
	if buildReportServices(plan, nil, []VulnSummary{{Severity: "high", Scope: "app:loose"}}) != nil {
		t.Fatal("assessment without services produced a services overview")
	}
}

func TestOrderScopesByServiceGroupsAndLabels(t *testing.T) {
	plan := servicesReportPlan()
	scopes := []reportScope{
		{ID: "app:loose", Kind: "host", Target: "https://portal.example.test"},
		{ID: "app:svc-2-url-1", Kind: "host", Target: "http://172.30.3.10:31132"},
		{ID: "host:svc-1-image", Kind: "host", Target: "hub.example.test/bcrs/auth:6"},
		{ID: "app:svc-1-url-1", Kind: "host", Target: "http://172.30.3.142:30862"},
	}
	orderScopesByService(scopes, plan)
	want := []string{"host:svc-1-image", "app:svc-1-url-1", "app:svc-2-url-1", "app:loose"}
	for i, id := range want {
		if scopes[i].ID != id {
			t.Fatalf("order %d: got %s want %s (%+v)", i, scopes[i].ID, id, scopes)
		}
	}
	if scopes[0].Service != "Auth Service" || scopes[3].Service != "" {
		t.Fatalf("service labels: %+v", scopes)
	}
	if label := reportScopeLabel(scopes[2]); label != "SERVICE  Common Service  ·  HOST  http://172.30.3.10:31132" {
		t.Fatalf("label %q", label)
	}
}

func TestGenerateReportWithManyServices(t *testing.T) {
	s := newTestServer(t, nil)
	scanDir := filepath.Join(s.dataDir, "bcrs", "2026-11-12", "scan-services")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &ScanRecord{ID: "scan-services", Name: "BCRS QA", Target: "BCRS microservices", Status: "finished", StartedAt: time.Now().Add(-time.Hour).Format(time.RFC3339), FinishedAt: time.Now().Format(time.RFC3339)}
	for i := 0; i < 40; i++ {
		rec.ReportServices = append(rec.ReportServices, reportService{Name: fmt.Sprintf("Service %02d with a fairly long descriptive name", i), Targets: []string{fmt.Sprintf("http://172.30.3.%d:3%04d", i, i), "hub.example.test/bcrs/service:1"}, Counts: map[string]int{"high": i % 3, "info": 1}, Findings: i%3 + 1, Auth: "token applied, not verified", Completed: 4, Failed: i % 2})
		rec.Vulns = append(rec.Vulns, VulnSummary{Title: "Finding", Severity: "high", Scope: fmt.Sprintf("app:svc-%d", i)})
	}
	path, err := s.generateReportAt(rec, scanDir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() < 1000 {
		t.Fatalf("report not written: %v", err)
	}
}

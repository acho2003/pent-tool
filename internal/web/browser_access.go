package web

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/credentials"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func (s *Server) verifyBrowserCredential(ctx context.Context, appURL, verifyURL, marker string, headers []string, storage *credentials.BrowserStorage, negative bool) error {
	if !scanner.UnifiedWorkflowEnabled() {
		return fmt.Errorf("browser access testing requires the expanded workflow flag")
	}
	if marker == "" {
		return fmt.Errorf("browser access testing requires a protected-route response marker")
	}
	if s.cfg.BrowserPath == "" {
		return fmt.Errorf("Chromium is unavailable for browser access testing")
	}
	dir, err := os.MkdirTemp("", "xalgorix-access-test-")
	if err != nil {
		return fmt.Errorf("browser access test storage unavailable")
	}
	defer os.RemoveAll(dir)
	scope := applicationScope(appURL)
	cfg := scanner.Config{KatanaChromePath: s.cfg.BrowserPath, KatanaTimeout: 20 * time.Second, WebMaxEndpoints: 40, ScopeGuard: func(raw string, _ []string) (bool, string) {
		if s.isBlockedTargetForScan(raw, nil) {
			return true, "target blocked by application scope guard"
		}
		return false, ""
	}}
	request := scanner.Request{Target: verifyURL, ScanDir: dir, AppScope: &scope, BrowserStorage: storage, BrowserAccessTest: true, BrowserCheckpointMarker: marker, TargetAuth: strings.Join(headers, "\n"), AuthRefresh: func(_ context.Context, current []string) ([]string, error) { return current, nil }}
	run := scanner.DiscoverBrowser(ctx, request, cfg)
	if run.AuthState != "verified" || run.Status != "completed" {
		return fmt.Errorf("browser protected-route verification failed")
	}
	if negative {
		request.TargetAuth, request.BrowserStorage = "", nil
		request.ScanDir = dir + "/anonymous"
		anonymous := scanner.DiscoverBrowser(ctx, request, cfg)
		if anonymous.AuthState == "verified" {
			return fmt.Errorf("browser marker is also visible without credentials; negative control failed")
		}
		if anonymous.Status != "failed" || anonymous.Reason != "browser protected-route marker was not confirmed" {
			return fmt.Errorf("browser anonymous negative control could not be evaluated")
		}
	}
	return nil
}

func (s *Server) assessmentBrowserStorage(plan *scanner.AssessmentPlan) map[string]*credentials.BrowserStorage {
	result := map[string]*credentials.BrowserStorage{}
	if plan == nil || plan.Config.WorkflowVersion != "unified-v1" {
		return result
	}
	if len(plan.AuthContexts) > 0 {
		for _, auth := range plan.AuthContexts {
			if auth.Primary && auth.State == "verified" && auth.BrowserStorage != nil {
				result[auth.TargetID] = auth.BrowserStorage
			}
		}
		return result
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		return result
	}
	for _, binding := range plan.Config.Access {
		if !webAuthenticationKind(binding.Kind) {
			continue
		}
		for _, id := range binding.TargetIDs {
			if record, err := vault.Get(binding.CredentialID, id); err == nil && record.BrowserStorage != nil {
				result[id] = record.BrowserStorage
			}
		}
	}
	return result
}

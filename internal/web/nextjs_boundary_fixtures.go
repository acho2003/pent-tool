package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func (s *Server) validateNextjsBoundaryFixtures(plan *scanner.AssessmentPlan) {
	store := apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}
	read := func(ref string) ([]byte, error) {
		file, err := store.Open(ref)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		if err != nil || len(body) == 0 || len(body) > 64<<10 {
			return nil, fmt.Errorf("bounded boundary fixture unavailable")
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != ref {
			return nil, fmt.Errorf("boundary fixture checksum mismatch")
		}
		return body, nil
	}
	add := func(message string) {
		plan.Errors = append(plan.Errors, assessment.Problem{Code: "nextjs_boundary.fixture", Message: message, Blocking: true})
	}
	for _, approval := range plan.Config.NextjsBoundaryApprovals {
		raw, err := read(approval.FixtureRef)
		if err != nil {
			add("Boundary manifest fixture is missing, corrupt, or oversized")
			continue
		}
		var target assessment.Target
		for _, candidate := range plan.Config.Targets {
			if candidate.ID == approval.TargetID {
				target = candidate
				break
			}
		}
		scope := assessment.AppScopeForTarget(plan.Config, approval.TargetID)
		f, err := scanner.ValidateNextjsBoundaryManifest(raw, target.Value, scope)
		if err != nil {
			add(err.Error())
			continue
		}
		if f.Kind != approval.Kind {
			add("Boundary manifest kind differs from its approval")
			continue
		}
		if f.CleanupBodyRef != "" {
			if _, err := read(f.CleanupBodyRef); err != nil {
				add("Boundary cleanup body is missing, corrupt, or oversized")
			}
		}
	}
}

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

func (s *Server) validateNextjsActionFixtures(plan *scanner.AssessmentPlan) {
	store := apifixture.Store{Dir: filepath.Join(s.dataDir, "_api_fixtures")}
	read := func(ref string) ([]byte, error) {
		file, err := store.Open(ref)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		if err != nil || len(data) == 0 || len(data) > 64<<10 {
			return nil, fmt.Errorf("bounded action fixture unavailable")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != ref {
			return nil, fmt.Errorf("action fixture checksum mismatch")
		}
		return data, nil
	}
	add := func(message string) {
		plan.Errors = append(plan.Errors, assessment.Problem{Code: "nextjs_action.fixture", Message: message, Blocking: true})
	}
	for _, a := range plan.Config.NextjsActionApprovals {
		raw, err := read(a.FixtureRef)
		if err != nil {
			add("Server Action manifest fixture is missing or corrupt")
			continue
		}
		var target assessment.Target
		for _, candidate := range plan.Config.Targets {
			if candidate.ID == a.TargetID {
				target = candidate
				break
			}
		}
		scope := assessment.AppScopeForTarget(plan.Config, a.TargetID)
		fixture, err := scanner.ValidateNextjsActionManifest(raw, target.Value, scope)
		if err != nil {
			add(err.Error())
			continue
		}
		for _, ref := range []string{fixture.BodyRef, fixture.CleanupBodyRef} {
			if ref == "" {
				continue
			}
			body, err := read(ref)
			if err != nil || len(body) == 0 || len(body) > 64<<10 {
				add("Server Action body or cleanup fixture is missing, corrupt, or larger than 64 KiB")
			}
		}
	}
}

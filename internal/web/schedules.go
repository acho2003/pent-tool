package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// scheduleIDPattern validates schedule IDs to prevent path traversal.
var scheduleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// handleSchedules handles GET /api/schedules and POST /api/schedules
func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.schedulesMu.RLock()
		defer s.schedulesMu.RUnlock()
		list := make([]*ScanSchedule, 0, len(s.schedules))
		for _, sch := range s.schedules {
			list = append(list, sch)
		}
		// Sort by Name alphabetically
		sort.Slice(list, func(i, j int) bool {
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
		_ = json.NewEncoder(w).Encode(list)
		return
	case http.MethodPost:
		var req ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.normalizeScheduleForExecution(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Assessment != nil {
			workflowConfig := newAssessmentWorkflowConfig(*req.Assessment)
			req.Assessment = &workflowConfig
			plan := s.buildAssessmentPlan(*req.Assessment)
			if req.PlanFingerprint == "" || req.PlanFingerprint != plan.Fingerprint || len(plan.Errors) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "scheduled assessment requires a current reviewed plan fingerprint", "plan": plan})
				return
			}
		}
		if req.Name == "" {
			req.Name = "Scheduled Scan " + strings.Join(req.Targets, ", ")
		}
		if req.Interval == "" {
			req.Interval = "daily"
		}
		normalizeScheduleActivity(&req)
		if err := normalizeScheduleTiming(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The review state is server-owned: a new schedule was just reviewed.
		req.setReview("")
		req.LastSkippedAt = time.Time{}
		req.ID = randomSlug()
		req.Enabled = true
		req.NextRun = calculateNextRun(&req, time.Now())

		s.schedulesMu.Lock()
		s.schedules[req.ID] = &req
		diskCopy := req // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()

		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			log.Printf("[SCHEDULER] Error saving schedule to disk: %v", err)
			http.Error(w, "failed to save schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(req)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleScheduleDetail handles GET /api/schedules/{id}, PUT /api/schedules/{id}, DELETE /api/schedules/{id}, and POST /api/schedules/{id}/trigger
func (s *Server) handleScheduleDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/schedules/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	if !scheduleIDPattern.MatchString(id) {
		http.Error(w, "invalid schedule id", http.StatusBadRequest)
		return
	}

	s.schedulesMu.RLock()
	sch, exists := s.schedules[id]
	s.schedulesMu.RUnlock()

	if !exists {
		http.Error(w, "schedule not found", http.StatusNotFound)
		return
	}

	// Handle trigger action
	if len(parts) > 1 && parts[1] == "trigger" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.schedulesMu.RLock()
		typedConfig, reviewedFingerprint := sch.Assessment, sch.PlanFingerprint
		s.schedulesMu.RUnlock()
		if typedConfig != nil {
			plan := s.buildAssessmentPlan(*typedConfig)
			if reason := scheduleReviewReason(plan, reviewedFingerprint); reason != "" {
				s.schedulesMu.Lock()
				changed := sch.PlanFingerprint == reviewedFingerprint && sch.setReview(reason)
				diskCopy := *sch // snapshot under lock for race-free disk write
				s.schedulesMu.Unlock()
				if changed {
					if err := s.saveScheduleToDisk(&diskCopy); err != nil {
						log.Printf("[SCHEDULER] Error saving review state of schedule %s: %v", diskCopy.ID, err)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "scheduled assessment plan changed; preview and save it again", "review_state": ScheduleReviewNeeded, "review_reason": reason, "plan": plan})
				return
			}
		}

		// Manually trigger the scan
		req := ScanRequest{
			Assessment:      sch.Assessment,
			PlanFingerprint: sch.PlanFingerprint,
			Profile:         sch.Profile,
			Targets:         sch.Targets,
			Instruction:     sch.Instruction,
			ScanMode:        sch.ScanMode,
			SeverityFilter:  sch.SeverityFilter,
			Scanners:        append([]string(nil), sch.Scanners...),
			Phases:          sch.Phases,
			ReconMode:       sch.ReconMode,
			ScanIntensity:   sch.ScanIntensity,
			CompanyName:     sch.CompanyName,
			LogoPath:        sch.LogoPath,
			DiscordWebhook:  sch.DiscordWebhook,
			Name:            sch.Name + " (Scheduled)",
			Artifact:        sch.Artifact,
			VulsSSHHost:     sch.VulsSSHHost,
		}

		scanCfg := *s.cfg
		instanceID := randomSlug()

		go s.runMultiScan(req, &scanCfg, instanceID)

		s.schedulesMu.Lock()
		sch.LastRun = time.Now()
		diskCopy := *sch // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()
		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			log.Printf("[SCHEDULER] Failed to persist schedule %s after manual trigger: %v", diskCopy.ID, err)
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "triggered", "instance_id": instanceID})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(sch)
		return

	case http.MethodPut:
		var req ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.normalizeScheduleForExecution(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Assessment != nil {
			workflowConfig := newAssessmentWorkflowConfig(*req.Assessment)
			req.Assessment = &workflowConfig
			plan := s.buildAssessmentPlan(*req.Assessment)
			if req.PlanFingerprint == "" || req.PlanFingerprint != plan.Fingerprint || len(plan.Errors) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "scheduled assessment plan changed; preview and save it again", "plan": plan})
				return
			}
		}
		normalizeScheduleActivity(&req)
		if err := normalizeScheduleTiming(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.schedulesMu.Lock()
		oldEnabled := sch.Enabled
		oldTiming := sch.timing()

		sch.Name = req.Name
		sch.Interval = req.Interval
		sch.RunAt = req.RunAt
		sch.RunDay = req.RunDay
		sch.Timezone = req.Timezone
		sch.Enabled = req.Enabled
		sch.Targets = req.Targets
		sch.Instruction = req.Instruction
		sch.ScanMode = req.ScanMode
		sch.Profile = req.Profile
		sch.SeverityFilter = req.SeverityFilter
		sch.Scanners = append([]string(nil), req.Scanners...)
		sch.Phases = req.Phases
		sch.ReconMode = req.ReconMode
		sch.ScanIntensity = req.ScanIntensity
		sch.CompanyName = req.CompanyName
		sch.LogoPath = req.LogoPath
		sch.DiscordWebhook = req.DiscordWebhook
		sch.Model = req.Model
		sch.Artifact = req.Artifact
		sch.VulsSSHHost = req.VulsSSHHost
		if req.Assessment != nil {
			// The operator re-previewed and accepted the current plan, which
			// clears any needs-review state. A PUT without an assessment (an
			// older client editing name or timing) keeps the reviewed plan.
			sch.Assessment = req.Assessment
			sch.PlanFingerprint = req.PlanFingerprint
			sch.setReview("")
		}

		// If any timing field changed, or enabled transitioned false -> true, recalculate NextRun
		if sch.timing() != oldTiming || (sch.Enabled && !oldEnabled) {
			sch.NextRun = calculateNextRun(sch, time.Now())
		}

		diskCopy := *sch // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()

		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			http.Error(w, "failed to save schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(&diskCopy)
		return

	case http.MethodDelete:
		s.schedulesMu.Lock()
		delete(s.schedules, id)
		s.schedulesMu.Unlock()

		if err := s.deleteScheduleFromDisk(id); err != nil {
			http.Error(w, "failed to delete schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func normalizeDeterministicSchedule(sch *ScanSchedule) error {
	if sch.ScanMode == "" || sch.ScanMode == "dast" || sch.ScanMode == "source" {
		sch.ScanMode = "single"
	}
	if sch.ScanMode != "single" && sch.ScanMode != "wildcard" {
		return fmt.Errorf("scan_mode must be single or wildcard")
	}
	if sch.Artifact.Ref != "" {
		sch.Artifact.Kind = strings.ToLower(strings.TrimSpace(sch.Artifact.Kind))
		switch sch.Artifact.Kind {
		case "filesystem", "repository", "image", "sbom":
		default:
			return fmt.Errorf("artifact.kind must be filesystem, repository, image, or sbom")
		}
	}
	if len(sch.Targets) == 0 && sch.Artifact.Ref != "" {
		sch.Targets = []string{"artifact://" + sch.Artifact.Kind}
	}
	if len(sch.Targets) == 0 {
		return fmt.Errorf("targets are required (or provide an artifact)")
	}
	selected, err := scanner.NormalizeScanners(sch.Scanners)
	if err != nil {
		return err
	}
	sch.Scanners = selected
	return nil
}

func (s *Server) normalizeScheduleForExecution(sch *ScanSchedule) error {
	if sch.Assessment == nil {
		return normalizeDeterministicSchedule(sch)
	}
	config := assessment.Normalize(*sch.Assessment)
	if sch.Profile != "" && config.Profile != "" && sch.Profile != config.Profile {
		return fmt.Errorf("profile conflicts with assessment.profile")
	}
	if sch.Profile == "" {
		sch.Profile = config.Profile
	}
	if sch.Profile == "" {
		sch.Profile = scanner.ProfileGentle
	}
	if _, ok := scanner.ResolveWebProfile(sch.Profile); !ok {
		return fmt.Errorf("profile must be web-gentle or web-thorough")
	}
	config.Profile = sch.Profile
	for _, problem := range assessment.Validate(config) {
		if problem.Blocking {
			return fmt.Errorf("%s", problem.Message)
		}
	}
	canonicalTargets := make([]string, 0, len(config.Targets))
	for _, target := range config.Targets {
		canonicalTargets = append(canonicalTargets, target.Value)
	}
	if len(sch.Targets) == 0 {
		sch.Targets = canonicalTargets
	} else if !slices.Equal(sch.Targets, canonicalTargets) {
		return fmt.Errorf("schedule targets conflict with assessment_targets")
	}
	sch.Assessment = &config
	sch.ScanMode = "single"
	sch.PlanFingerprint = strings.TrimSpace(sch.PlanFingerprint)
	return nil
}

package scanner

import (
	"fmt"
	"slices"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// expandTLSServiceJobs pins each TLS run to one approved hostname/SNI and port.
// HTTP origins are not silently scanned on their hostname's HTTPS port.
func expandTLSServiceJobs(cfg assessment.AssessmentConfig, jobs []PlanJob) []PlanJob {
	if !slices.Contains(cfg.Types, assessment.TypeWebApplication) && !slices.Contains(cfg.Types, assessment.TypeAPI) {
		return jobs
	}
	targets := map[string]assessment.Target{}
	for _, target := range cfg.Targets {
		targets[target.ID] = target
	}
	out := make([]PlanJob, 0, len(jobs))
	for _, job := range jobs {
		if job.Scanner != "testssl" && job.Scanner != "sslyze" {
			out = append(out, job)
			continue
		}
		target, ok := targets[job.TargetID]
		if !ok || (target.Kind != assessment.KindURL && target.Kind != assessment.KindDomain && target.Kind != assessment.KindHost) {
			out = append(out, job)
			continue
		}
		scope := assessment.AppScopeForTarget(cfg, target.ID)
		seen := map[string]bool{}
		count := 0
		for _, origin := range scope.Origins() {
			if origin.Scheme != "https" {
				continue
			}
			service := origin.Origin()
			if seen[service] {
				continue
			}
			seen[service] = true
			perService := job
			perService.Target = service
			perService.Variant = fmt.Sprintf("%s:%s:%d", job.Scanner, origin.Host, origin.Port)
			perService.ID = job.ID + ":" + service
			out = append(out, perService)
			count++
		}
		if count == 0 {
			job.State = PlanSkipped
			job.Reason = "no approved HTTPS service for this target"
			out = append(out, job)
		}
	}
	return out
}

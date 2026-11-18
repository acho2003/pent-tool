package web

import (
	"github.com/acho2003/pent-tool/internal/assessment"
	"github.com/acho2003/pent-tool/internal/scanner"
)

// Mark only newly previewed/accepted requests. Saved-plan revalidation does not
// call this function, so enabling rollout never upgrades an existing executor.
func newAssessmentWorkflowConfig(cfg assessment.AssessmentConfig) assessment.AssessmentConfig {
	if cfg.WorkflowVersion != "" || !scanner.UnifiedWorkflowEnabled() {
		return cfg
	}
	for _, typ := range cfg.Types {
		if typ == assessment.TypeWebApplication || typ == assessment.TypeAPI || typ == assessment.TypeNetwork {
			cfg.WorkflowVersion = "unified-v1"
			break
		}
	}
	return cfg
}

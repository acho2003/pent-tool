package web

import (
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// assessmentCloudCredentials resolves target-bound cloud credentials from the
// vault for the cloud posture-audit adapters (prowler/scoutsuite). The vault
// record stores the exact credential environment variables the tool expects
// (e.g. AWS_ACCESS_KEY_ID) plus an optional "provider" value; nothing here is
// persisted to scan records — the map is passed to the runner at execution time
// and the runner injects it via env only. A missing/failed lookup simply yields
// no credential for that target, so the job records an explicit "unavailable".
func (s *Server) assessmentCloudCredentials(plan *scanner.AssessmentPlan) map[string]scanner.CloudCredential {
	creds := map[string]scanner.CloudCredential{}
	if plan == nil {
		return creds
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		return creds
	}
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessCloud {
			continue
		}
		for _, id := range binding.TargetIDs {
			record, getErr := vault.Get(binding.CredentialID, id)
			if getErr != nil || record.Kind != assessment.AccessCloud {
				continue
			}
			env := map[string]string{}
			provider := ""
			for k, v := range record.Values {
				if strings.EqualFold(k, "provider") {
					provider = strings.ToLower(strings.TrimSpace(v))
					continue
				}
				if strings.TrimSpace(v) == "" {
					continue
				}
				env[k] = v
			}
			if len(env) == 0 {
				continue
			}
			creds[id] = scanner.CloudCredential{Provider: provider, Env: env}
		}
	}
	return creds
}

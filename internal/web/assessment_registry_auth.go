package web

import (
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// assessmentRegistryCredentials resolves target-bound private registry logins
// for Trivy image scans. Like cloud credentials, the values are passed to the
// runner at execution time only (through the child environment) and are never
// persisted to scan records. A missing or invalid record yields no credential,
// so the image scan runs without one and Trivy reports any pull failure.
func (s *Server) assessmentRegistryCredentials(plan *scanner.AssessmentPlan) map[string]scanner.RegistryCredential {
	creds := map[string]scanner.RegistryCredential{}
	if plan == nil {
		return creds
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		return creds
	}
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessRegistryCreds {
			continue
		}
		for _, id := range binding.TargetIDs {
			record, getErr := vault.Get(binding.CredentialID, id)
			if getErr != nil || record.Kind != assessment.AccessRegistryCreds {
				continue
			}
			cred := scanner.RegistryCredential{
				Registry: strings.TrimSpace(record.Values["registry"]),
				Username: strings.TrimSpace(record.Values["username"]),
				Password: record.Values["password"],
			}
			if cred.Registry == "" || cred.Username == "" || cred.Password == "" || strings.ContainsAny(cred.Username+cred.Password, "\r\n\x00") {
				continue
			}
			creds[id] = cred
		}
	}
	return creds
}

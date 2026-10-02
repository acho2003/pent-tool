package web

import (
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

// assessmentRepositoryCredentials resolves target-bound repository tokens from
// the vault for cloning private repositories. The vault record holds "token"
// and an optional "username"; nothing here is persisted to scan records — the
// map is passed to the clone step at execution time, which hands the token to
// git via env only. A missing lookup yields no credential, so a private
// repository reports an explicit clone refusal instead.
func (s *Server) assessmentRepositoryCredentials(plan *scanner.AssessmentPlan) map[string]scanner.RepoCredential {
	creds := map[string]scanner.RepoCredential{}
	if plan == nil {
		return creds
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		return creds
	}
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessRepositoryCreds {
			continue
		}
		for _, id := range binding.TargetIDs {
			record, getErr := vault.Get(binding.CredentialID, id)
			if getErr != nil || record.Kind != assessment.AccessRepositoryCreds {
				continue
			}
			token := strings.TrimSpace(record.Values["token"])
			if token == "" {
				continue
			}
			creds[id] = scanner.RepoCredential{Username: strings.TrimSpace(record.Values["username"]), Token: token}
		}
	}
	return creds
}

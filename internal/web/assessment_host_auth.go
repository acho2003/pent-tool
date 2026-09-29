package web

import (
	"regexp"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

var assessmentSSHAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Host aliases refer to operator-managed SSH configuration. Only opaque
// aliases, never passwords or private keys, reach scanner command arguments.
func (s *Server) assessmentHostAliases(plan *scanner.AssessmentPlan) (map[string]string, error) {
	aliases := map[string]string{}
	if plan == nil {
		return aliases, nil
	}
	needsSSH := false
	for _, binding := range plan.Config.Access {
		needsSSH = needsSSH || binding.Kind == assessment.AccessSSH
	}
	if !needsSSH {
		return aliases, nil
	}
	vault, err := s.openCredentialVault()
	if err != nil {
		return aliases, nil // credentialed host jobs will be skipped explicitly
	}
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessSSH {
			continue
		}
		for _, id := range binding.TargetIDs {
			record, err := vault.Get(binding.CredentialID, id)
			if err != nil || record.Kind != assessment.AccessSSH {
				continue
			}
			alias := strings.TrimSpace(record.Values["ssh_alias"])
			if assessmentSSHAliasPattern.MatchString(alias) {
				aliases[id] = alias
			}
		}
	}
	return aliases, nil
}

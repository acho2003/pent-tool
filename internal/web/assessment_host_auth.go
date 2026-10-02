package web

import (
	"regexp"
	"strconv"
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

func (s *Server) assessmentGVMSSHCredentials(plan *scanner.AssessmentPlan) (map[string]scanner.GVMSSHCredential, map[string]bool) {
	credentials := map[string]scanner.GVMSSHCredential{}
	requested := map[string]bool{}
	if plan == nil {
		return credentials, requested
	}
	vault, err := s.openCredentialVault()
	for _, binding := range plan.Config.Access {
		if binding.Kind != assessment.AccessSSH {
			continue
		}
		for _, id := range binding.TargetIDs {
			requested[id] = true
			if err != nil {
				continue
			}
			record, getErr := vault.Get(binding.CredentialID, id)
			if getErr != nil || record.Kind != assessment.AccessSSH {
				continue
			}
			credentialID := strings.TrimSpace(record.Values["gvm_credential_id"])
			if !assessmentGVMCredentialPattern.MatchString(credentialID) {
				continue
			}
			port := 22
			if value := strings.TrimSpace(record.Values["gvm_ssh_port"]); value != "" {
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil || parsed < 1 || parsed > 65535 {
					continue
				}
				port = parsed
			}
			credentials[id] = scanner.GVMSSHCredential{ID: credentialID, Port: port}
		}
	}
	return credentials, requested
}

var assessmentGVMCredentialPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

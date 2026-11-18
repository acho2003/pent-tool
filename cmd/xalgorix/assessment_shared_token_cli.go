package main

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/acho2003/pent-tool/internal/assessment"
	"github.com/acho2003/pent-tool/internal/credentials"
)

const maxSharedTokenBytes = 1 << 16

// sharedTokenRequested reports whether the CLI was asked to expand a system
// template with a shared token.
func sharedTokenRequested(args cliArgs) bool {
	return strings.TrimSpace(args.systemTemplate) != ""
}

// expandSystemTemplateIntoConfig expands a system template over the --services
// names and appends the resulting path-scoped targets and service groupings to
// cfg. When a --shared-token-file is supplied it also stages the token in a
// transient in-memory vault and adds one per-service access binding, returning
// that vault; without a token file it returns a nil vault (an unauthenticated
// expanded preview/run). The token value never touches disk and is never placed
// on the command line.
//
// It mutates cfg in place and sets WorkflowVersion so authenticated OpenAPI
// discovery is eligible (subject to XALGORIX_UNIFIED_WORKFLOW at run time).
func expandSystemTemplateIntoConfig(cfg *assessment.AssessmentConfig, args cliArgs) (*credentials.Vault, error) {
	if len(cfg.Access) > 0 {
		return nil, fmt.Errorf("--system-template cannot be combined with access bindings in the assessment config")
	}
	tpl, err := loadSystemTemplateFile(args.systemTemplate)
	if err != nil {
		return nil, err
	}
	exp, err := assessment.ExpandSystemTemplate(tpl, args.services, args.baseOverride)
	if err != nil {
		return nil, err
	}

	cfg.Targets = append(cfg.Targets, exp.Targets...)
	cfg.Services = append(cfg.Services, exp.Services...)
	cfg.WorkflowVersion = "unified-v1"

	if strings.TrimSpace(args.sharedTokenFile) == "" {
		return nil, nil // expanded, but no shared token: unauthenticated
	}

	values, err := parseSharedTokenFile(args.sharedTokenFile, exp.HeaderName, exp.HeaderPrefix)
	if err != nil {
		return nil, err
	}
	vault, err := newTransientVault()
	if err != nil {
		return nil, err
	}
	meta, err := vault.Create(credentials.Record{
		Name:      "shared-token",
		Kind:      assessment.AccessApplicationHeaders,
		TargetIDs: exp.AuthTargetIDs,
		Values:    values,
	})
	if err != nil {
		return nil, fmt.Errorf("stage shared token: %w", err)
	}
	for _, item := range exp.Items {
		cfg.Access = append(cfg.Access, assessment.AccessBinding{
			TargetIDs:    []string{item.TargetID},
			Kind:         assessment.AccessApplicationHeaders,
			CredentialID: meta.ID,
			VerifyURL:    exp.VerifyByID[item.TargetID],
			VerifyMarker: tpl.VerifyMarker,
		})
	}
	return vault, nil
}

func loadSystemTemplateFile(path string) (assessment.SystemTemplate, error) {
	var tpl assessment.SystemTemplate
	f, err := os.Open(path)
	if err != nil {
		return tpl, fmt.Errorf("open system template: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSharedTokenBytes+1))
	if err != nil {
		return tpl, fmt.Errorf("read system template: %w", err)
	}
	if len(data) > maxSharedTokenBytes {
		return tpl, fmt.Errorf("system template exceeds %d bytes", maxSharedTokenBytes)
	}
	if err := json.Unmarshal(data, &tpl); err != nil {
		return tpl, fmt.Errorf("decode system template: %w", err)
	}
	tpl = tpl.WithDefaults()
	if p := assessment.FirstBlocking(tpl.Validate()); p != nil {
		return tpl, fmt.Errorf("invalid system template: %s", p.Message)
	}
	return tpl, nil
}

// parseSharedTokenFile reads the shared token from a file. Each non-empty,
// non-comment line is either a full "Header-Name: value" header or, for a single
// bare line, the raw token which is wrapped with the template's header name and
// prefix. The token is never read from argv.
func parseSharedTokenFile(path, headerName, headerPrefix string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read shared token file: %w", err)
	}
	if len(raw) > maxSharedTokenBytes {
		return nil, fmt.Errorf("shared token file exceeds %d bytes", maxSharedTokenBytes)
	}
	values := map[string]string{}
	var bareLines []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if name, value, ok := strings.Cut(trimmed, ":"); ok && strings.TrimSpace(name) != "" {
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if value == "" {
				return nil, fmt.Errorf("header %q has no value", name)
			}
			values[name] = value
			continue
		}
		bareLines = append(bareLines, trimmed)
	}
	if len(bareLines) == 1 && len(values) == 0 {
		values[headerName] = headerPrefix + bareLines[0]
	} else if len(bareLines) > 0 {
		return nil, fmt.Errorf("shared token file mixes a bare token with header lines; use either one bare token or \"Header: value\" lines")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("shared token file contains no token")
	}
	return values, nil
}

func newTransientVault() (*credentials.Vault, error) {
	key := make([]byte, credentials.KeySize)
	if _, err := cryptorand.Read(key); err != nil {
		return nil, err
	}
	// Open does not touch disk; swap in an in-memory backend so the staged
	// credential lives only in this process.
	vault, err := credentials.Open("", key)
	if err != nil {
		return nil, err
	}
	vault.UseBlobs(credentials.MemoryBlobStore())
	return vault, nil
}

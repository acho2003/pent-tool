package main

import (
	"fmt"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

// headerAuthRequested reports whether the CLI was asked to authenticate a URL
// assessment with headers (a cookie and/or bearer token) read from a file.
func headerAuthRequested(args cliArgs) bool {
	return strings.TrimSpace(args.authHeaderFile) != ""
}

// cliAuthRequested reports whether the CLI itself mints the access bindings
// (from --shared-token-file or --auth-header-file), so the generic "cannot
// resolve credential references" refusal does not apply.
func cliAuthRequested(args cliArgs) bool {
	return sharedTokenRequested(args) || headerAuthRequested(args)
}

// applyHeaderFileAuthToConfig reads auth header lines from --auth-header-file and
// binds them to every HTTP(S) target already in cfg (typically a single
// whole-origin --target), reusing the same transient in-memory vault and access
// plumbing as the shared-token microservice path.
//
// Unlike --system-template it does not rewrite target scope: the operator's
// --target decides scope, so a bare origin stays whole-origin and the
// authenticated browser crawl covers the whole app. The header values never
// touch disk and are never placed on the command line.
//
// The file holds full "Header: value" lines (for example "Cookie: a=b; c=d"
// and/or "Authorization: Bearer <token>") or a single bare token, which is
// wrapped as "Authorization: Bearer <token>". It sets WorkflowVersion so the
// authenticated browser crawl and OpenAPI discovery are eligible (subject to
// XALGORIX_UNIFIED_WORKFLOW at run time).
func applyHeaderFileAuthToConfig(cfg *assessment.AssessmentConfig, args cliArgs) (*credentials.Vault, error) {
	if len(cfg.Access) > 0 {
		return nil, fmt.Errorf("--auth-header-file cannot be combined with access bindings in the assessment config")
	}
	var urlTargetIDs []string
	for _, t := range cfg.Targets {
		if t.Kind == assessment.KindURL {
			urlTargetIDs = append(urlTargetIDs, t.ID)
		}
	}
	if len(urlTargetIDs) == 0 {
		return nil, fmt.Errorf("--auth-header-file requires at least one HTTP(S) --target")
	}

	// Reuse the shared-token file parser: it accepts full "Header: value" lines
	// or a single bare token (wrapped with the default Authorization/Bearer
	// convention), and reads the secret from the file, never argv.
	values, err := parseSharedTokenFile(args.authHeaderFile, assessment.DefaultAuthHeaderName, assessment.DefaultAuthHeaderPrefix)
	if err != nil {
		return nil, err
	}

	vault, err := newTransientVault()
	if err != nil {
		return nil, err
	}
	meta, err := vault.Create(credentials.Record{
		Name:      "cli-header-auth",
		Kind:      assessment.AccessApplicationHeaders,
		TargetIDs: urlTargetIDs,
		Values:    values,
	})
	if err != nil {
		return nil, fmt.Errorf("stage auth header: %w", err)
	}

	cfg.WorkflowVersion = "unified-v1"
	verifyURL := strings.TrimSpace(args.authVerifyURL)
	verifyMarker := strings.TrimSpace(args.authVerifyMarker)
	for _, id := range urlTargetIDs {
		cfg.Access = append(cfg.Access, assessment.AccessBinding{
			TargetIDs:    []string{id},
			Kind:         assessment.AccessApplicationHeaders,
			CredentialID: meta.ID,
			VerifyURL:    verifyURL,
			VerifyMarker: verifyMarker,
		})
	}
	return vault, nil
}

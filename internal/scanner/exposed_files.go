package scanner

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
)

// exposedFilesCatalogVersion is part of the plan fingerprint. Keep it small.
// v2 adds the Next.js env family and framework config source paths.
const exposedFilesCatalogVersion = "exposed-files-v2"

type exposedFilesRunner struct{}

func (exposedFilesRunner) Name() string { return "exposed-files" }
func (exposedFilesRunner) Descriptor() Descriptor {
	return Descriptor{Name: "exposed-files", Summary: "Bounded read-only checks for exposed secret and backup files", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (exposedFilesRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runExposureCatalog(ctx, req, cfg, emit, "exposed-files", exposedFilesCatalogVersion, "exposed secret and backup files", exposedFilesCatalog, classifyExposedFile)
}

// exposedFilesCatalog probes for a small, curated set of files that frequently
// leak credentials or data when accidentally served: environment files,
// credential stores, private keys, config backups and database dumps. Each is a
// single read-only GET; the body is read only to confirm the file's signature
// and is never written anywhere.
var exposedFilesCatalog = []exposureCheck{
	{ID: "dotenv", Path: "/.env", Purpose: "Exposed .env environment file"},
	{ID: "dotenv-local", Path: "/.env.local", Purpose: "Exposed .env.local file"},
	{ID: "dotenv-prod", Path: "/.env.production", Purpose: "Exposed .env.production file"},
	{ID: "dotenv-bak", Path: "/.env.bak", Purpose: "Exposed .env backup"},
	{ID: "dotenv-dev", Path: "/.env.development", Purpose: "Exposed .env.development file"},
	{ID: "dotenv-dev-local", Path: "/.env.development.local", Purpose: "Exposed .env.development.local file"},
	{ID: "dotenv-test", Path: "/.env.test", Purpose: "Exposed .env.test file"},
	// Next.js framework config is server-side source; it is never meant to be
	// served and leaks rewrites, allowed image hosts, headers and env wiring.
	{ID: "nextjs-config-js", Path: "/next.config.js", Purpose: "Exposed Next.js configuration source"},
	{ID: "nextjs-config-mjs", Path: "/next.config.mjs", Purpose: "Exposed Next.js configuration source"},
	{ID: "nextjs-config-ts", Path: "/next.config.ts", Purpose: "Exposed Next.js configuration source"},
	{ID: "aws-credentials", Path: "/.aws/credentials", Purpose: "Exposed AWS credentials file"},
	{ID: "git-credentials", Path: "/.git-credentials", Purpose: "Exposed git credential store"},
	{ID: "npmrc", Path: "/.npmrc", Purpose: "Exposed npm configuration"},
	{ID: "htpasswd", Path: "/.htpasswd", Purpose: "Exposed htpasswd password file"},
	{ID: "ssh-key", Path: "/.ssh/id_rsa", Purpose: "Exposed SSH private key"},
	{ID: "php-config-bak", Path: "/config.php.bak", Purpose: "Exposed PHP config backup"},
	{ID: "wp-config-bak", Path: "/wp-config.php.bak", Purpose: "Exposed WordPress config backup"},
	{ID: "docker-compose", Path: "/docker-compose.yml", Purpose: "Exposed Docker Compose file"},
	{ID: "ds-store", Path: "/.DS_Store", Purpose: "Exposed macOS directory index"},
	{ID: "sql-backup", Path: "/backup.sql", Purpose: "Exposed SQL backup"},
	{ID: "sql-database", Path: "/database.sql", Purpose: "Exposed SQL database dump"},
	{ID: "sql-dump", Path: "/dump.sql", Purpose: "Exposed SQL dump"},
}

var (
	dotenvLine    = regexp.MustCompile(`(?m)^[A-Z_][A-Z0-9_]*=`)
	gitCredURL    = regexp.MustCompile(`https?://[^/\s]+:[^/@\s]+@`)
	htpasswdEntry = regexp.MustCompile(`(?m)^[^:\s]+:(\$(apr1|2[aby]|1|5|6)\$|\{SHA\}|[A-Za-z0-9./]{13}$)`)
	sqlDumpMarker = regexp.MustCompile(`(?i)(insert into|create table|mysql dump|postgresql database dump|drop table)`)
	// nextConfigShape matches keys that only appear in a Next.js config object,
	// keeping a generic served .js file from being misread as the config.
	nextConfigShape = regexp.MustCompile(`(?i)(nextconfig|reactstrictmode|experimental|\brewrites\b|\bredirects\b|\bimages\s*:|poweredbyheader|output\s*:\s*["']standalone["']|async\s+headers)`)
)

// classifyExposedFile confirms each response matches the target file's signature
// before reporting it. The verdict never carries the body: the shared driver's
// default evidence (status plus a header fingerprint) is used, so no secret
// value or key material is written to the findings artifact.
func classifyExposedFile(check exposureCheck, resp *http.Response, body []byte) exposureVerdict {
	if resp.StatusCode != http.StatusOK {
		return exposureVerdict{}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return exposureVerdict{}
	}
	text := string(trimmed)
	lower := strings.ToLower(text)
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	// An HTML body is a catch-all page, not the raw file.
	if strings.Contains(ct, "text/html") || strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return exposureVerdict{}
	}
	leak := func(sev, title string) exposureVerdict {
		return exposureVerdict{Classification: "sensitive_file_exposed", Severity: sev, Title: title}
	}
	switch check.ID {
	case "dotenv", "dotenv-local", "dotenv-prod", "dotenv-bak", "dotenv-dev", "dotenv-dev-local", "dotenv-test":
		if len(dotenvLine.FindAllIndex(trimmed, 2)) >= 2 {
			return leak("high", "Exposed environment file with configuration secrets")
		}
	case "nextjs-config-js", "nextjs-config-mjs", "nextjs-config-ts":
		// Confirm it is the config module, not an HTML route or 200 catch-all:
		// a module export plus a Next.js config shape marker.
		isModule := strings.Contains(text, "module.exports") || strings.Contains(text, "export default") || strings.Contains(text, "export const")
		hasConfigShape := nextConfigShape.MatchString(lower)
		if isModule && hasConfigShape {
			return leak("medium", "Exposed Next.js configuration source")
		}
	case "aws-credentials":
		if strings.Contains(lower, "aws_access_key_id") || strings.Contains(lower, "aws_secret_access_key") {
			return leak("high", "Exposed AWS credentials file")
		}
	case "git-credentials":
		if gitCredURL.Match(trimmed) {
			return leak("high", "Exposed git credential store")
		}
	case "npmrc":
		if strings.Contains(lower, "_authtoken") || strings.Contains(lower, "_password") || strings.Contains(lower, "registry=") {
			return leak("high", "Exposed npm credentials")
		}
	case "htpasswd":
		if htpasswdEntry.Match(trimmed) {
			return leak("high", "Exposed htpasswd password hashes")
		}
	case "ssh-key":
		if strings.Contains(text, "-----BEGIN") && strings.Contains(text, "PRIVATE KEY") {
			return leak("high", "Exposed SSH private key")
		}
	case "php-config-bak", "wp-config-bak":
		if strings.Contains(lower, "<?php") && (strings.Contains(lower, "password") || strings.Contains(lower, "define(") || strings.Contains(lower, "db_")) {
			return leak("high", "Exposed PHP configuration backup with credentials")
		}
	case "docker-compose":
		if strings.Contains(lower, "services:") && (strings.Contains(lower, "image:") || strings.Contains(lower, "environment:")) {
			return leak("medium", "Exposed Docker Compose configuration")
		}
	case "ds-store":
		if bytes.Contains(trimmed, []byte("Bud1")) {
			return leak("medium", "Exposed macOS .DS_Store directory index")
		}
	case "sql-backup", "sql-database", "sql-dump":
		if sqlDumpMarker.Match(trimmed) {
			return leak("high", "Exposed SQL database dump")
		}
	}
	return exposureVerdict{}
}

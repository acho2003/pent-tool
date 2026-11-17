package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// exposedFilesCatalogVersion is part of the plan fingerprint. Keep it small.
// v2 adds the Next.js env family and framework config source paths.
// v3 adds Next.js build-output artifacts served at the web root.
// v4 widens the .env family (environment/backup/template/key-file names) and
// adds application, infrastructure and tool configuration files.
// v5 adds Next.js/Vercel build and deployment files and NestJS/Node config,
// ORM, log, metrics and queue-dashboard paths.
const exposedFilesCatalogVersion = "exposed-files-v5"

type exposedFilesRunner struct{}

func (exposedFilesRunner) Name() string { return "exposed-files" }
func (exposedFilesRunner) Descriptor() Descriptor {
	return Descriptor{Name: "exposed-files", Summary: "Bounded read-only checks for exposed secret, environment, configuration and backup files", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (exposedFilesRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runExposureCatalog(ctx, req, cfg, emit, "exposed-files", exposedFilesCatalogVersion, "exposed secret and backup files", exposedFilesCatalog, classifyExposedFile)
}

// exposedFilesCatalog probes for a curated set of files that frequently leak
// credentials or data when accidentally served: environment files, credential
// stores, private keys, application and infrastructure configuration, config
// backups and database dumps. Each is a single read-only GET relative to the
// approved target path; the body is read only to confirm the file's signature
// and is never written anywhere. Entries are ordered by value so a request
// budget that runs out still covers the most damaging leaks first. Existing IDs
// are stable: they are part of each finding's identity.
var exposedFilesCatalog = []exposureCheck{
	// Environment files. Every ID starts with "dotenv"; templates use
	// "dotenv-template-" and are only reported when they hold real values.
	{ID: "dotenv", Path: "/.env", Purpose: "Exposed .env environment file"},
	{ID: "dotenv-local", Path: "/.env.local", Purpose: "Exposed .env.local file"},
	{ID: "dotenv-prod", Path: "/.env.production", Purpose: "Exposed .env.production file"},
	{ID: "dotenv-production-local", Path: "/.env.production.local", Purpose: "Exposed .env.production.local file"},
	{ID: "dotenv-prod-short", Path: "/.env.prod", Purpose: "Exposed .env.prod file"},
	{ID: "dotenv-bak", Path: "/.env.bak", Purpose: "Exposed .env backup"},
	{ID: "dotenv-prod-bak", Path: "/.env.prod.bak", Purpose: "Exposed production .env backup"},
	{ID: "dotenv-secret", Path: "/.env.secret", Purpose: "Exposed .env.secret file"},
	{ID: "dotenv-keys", Path: "/.env.keys", Purpose: "Exposed .env.keys decryption-key file"},
	{ID: "dotenv-vault", Path: "/.env.vault", Purpose: "Exposed .env.vault file"},
	{ID: "dotenv-staging", Path: "/.env.staging", Purpose: "Exposed .env.staging file"},
	{ID: "dotenv-stage", Path: "/.env.stage", Purpose: "Exposed .env.stage file"},
	{ID: "dotenv-preprod", Path: "/.env.preprod", Purpose: "Exposed .env.preprod file"},
	{ID: "dotenv-uat", Path: "/.env.uat", Purpose: "Exposed .env.uat file"},
	{ID: "dotenv-qa", Path: "/.env.qa", Purpose: "Exposed .env.qa file"},
	{ID: "dotenv-dev", Path: "/.env.development", Purpose: "Exposed .env.development file"},
	{ID: "dotenv-dev-local", Path: "/.env.development.local", Purpose: "Exposed .env.development.local file"},
	{ID: "dotenv-dev-short", Path: "/.env.dev", Purpose: "Exposed .env.dev file"},
	{ID: "dotenv-test", Path: "/.env.test", Purpose: "Exposed .env.test file"},
	{ID: "dotenv-test-local", Path: "/.env.test.local", Purpose: "Exposed .env.test.local file"},
	{ID: "dotenv-docker", Path: "/.env.docker", Purpose: "Exposed .env.docker file"},
	{ID: "dotenv-shared", Path: "/.env.shared", Purpose: "Exposed .env.shared file"},
	{ID: "dotenv-monorepo", Path: "/.env.monorepo", Purpose: "Exposed .env.monorepo file"},
	{ID: "dotenv-ci", Path: "/.env.ci", Purpose: "Exposed .env.ci file"},
	{ID: "dotenv-remote", Path: "/.env.remote", Purpose: "Exposed .env.remote file"},
	{ID: "dotenv-old", Path: "/.env.old", Purpose: "Exposed old .env copy"},
	{ID: "dotenv-orig", Path: "/.env.orig", Purpose: "Exposed original .env copy"},
	{ID: "dotenv-save", Path: "/.env.save", Purpose: "Exposed saved .env copy"},
	{ID: "dotenv-backup", Path: "/.env.backup", Purpose: "Exposed .env backup"},
	{ID: "dotenv-copy", Path: "/.env.copy", Purpose: "Exposed .env copy"},
	{ID: "dotenv-tilde", Path: "/.env~", Purpose: "Exposed editor backup of .env"},
	// `vercel pull` / `vercel env pull` writes real environment values here.
	{ID: "dotenv-vercel-production", Path: "/.vercel/.env.production.local", Purpose: "Exposed Vercel production environment file"},
	{ID: "dotenv-vercel-preview", Path: "/.vercel/.env.preview.local", Purpose: "Exposed Vercel preview environment file"},
	{ID: "dotenv-vercel-development", Path: "/.vercel/.env.development.local", Purpose: "Exposed Vercel development environment file"},
	// Credential stores and infrastructure state.
	{ID: "aws-credentials", Path: "/.aws/credentials", Purpose: "Exposed AWS credentials file"},
	{ID: "gcp-credentials", Path: "/credentials.json", Purpose: "Exposed Google Cloud credentials file"},
	{ID: "gcp-service-account", Path: "/service-account.json", Purpose: "Exposed Google Cloud service-account key"},
	{ID: "gcp-service-account-key", Path: "/serviceAccountKey.json", Purpose: "Exposed Google Cloud service-account key"},
	{ID: "kubeconfig", Path: "/.kube/config", Purpose: "Exposed Kubernetes kubeconfig"},
	{ID: "kubeconfig-root", Path: "/kubeconfig", Purpose: "Exposed Kubernetes kubeconfig"},
	{ID: "tfstate", Path: "/terraform.tfstate", Purpose: "Exposed Terraform state"},
	{ID: "tfstate-backup", Path: "/terraform.tfstate.backup", Purpose: "Exposed Terraform state backup"},
	{ID: "docker-config", Path: "/.docker/config.json", Purpose: "Exposed Docker registry credentials"},
	{ID: "git-credentials", Path: "/.git-credentials", Purpose: "Exposed git credential store"},
	{ID: "npmrc", Path: "/.npmrc", Purpose: "Exposed npm configuration"},
	{ID: "pypirc", Path: "/.pypirc", Purpose: "Exposed PyPI credentials"},
	{ID: "netrc", Path: "/.netrc", Purpose: "Exposed .netrc credentials"},
	{ID: "pgpass", Path: "/.pgpass", Purpose: "Exposed PostgreSQL password file"},
	{ID: "mycnf", Path: "/.my.cnf", Purpose: "Exposed MySQL client configuration"},
	{ID: "vscode-sftp", Path: "/.vscode/sftp.json", Purpose: "Exposed VS Code SFTP configuration"},
	{ID: "sublime-sftp", Path: "/sftp-config.json", Purpose: "Exposed Sublime SFTP configuration"},
	{ID: "htpasswd", Path: "/.htpasswd", Purpose: "Exposed htpasswd password file"},
	{ID: "ssh-key", Path: "/.ssh/id_rsa", Purpose: "Exposed SSH private key"},
	// Application configuration.
	{ID: "appsettings", Path: "/appsettings.json", Purpose: "Exposed ASP.NET Core appsettings"},
	{ID: "appsettings-prod", Path: "/appsettings.Production.json", Purpose: "Exposed ASP.NET Core production appsettings"},
	{ID: "appsettings-dev", Path: "/appsettings.Development.json", Purpose: "Exposed ASP.NET Core development appsettings"},
	{ID: "web-config", Path: "/web.config", Purpose: "Exposed ASP.NET web.config"},
	{ID: "spring-props", Path: "/application.properties", Purpose: "Exposed Spring application.properties"},
	{ID: "spring-yml", Path: "/application.yml", Purpose: "Exposed Spring application.yml"},
	{ID: "spring-prod-props", Path: "/application-prod.properties", Purpose: "Exposed Spring production properties"},
	{ID: "spring-prod-yml", Path: "/application-prod.yml", Purpose: "Exposed Spring production configuration"},
	{ID: "rails-master-key", Path: "/config/master.key", Purpose: "Exposed Rails master key"},
	{ID: "rails-secrets-yml", Path: "/config/secrets.yml", Purpose: "Exposed Rails secrets.yml"},
	{ID: "rails-database-yml", Path: "/config/database.yml", Purpose: "Exposed Rails database.yml"},
	{ID: "php-config-bak", Path: "/config.php.bak", Purpose: "Exposed PHP config backup"},
	{ID: "wp-config-bak", Path: "/wp-config.php.bak", Purpose: "Exposed WordPress config backup"},
	{ID: "config-json", Path: "/config.json", Purpose: "Exposed config.json"},
	{ID: "config-yml", Path: "/config.yml", Purpose: "Exposed config.yml"},
	{ID: "config-yaml", Path: "/config.yaml", Purpose: "Exposed config.yaml"},
	{ID: "settings-json", Path: "/settings.json", Purpose: "Exposed settings.json"},
	// NestJS / Node.js: ORM, node-config, process-manager and build config.
	{ID: "typeorm-ormconfig-json", Path: "/ormconfig.json", Purpose: "Exposed TypeORM ormconfig.json"},
	{ID: "typeorm-ormconfig-yml", Path: "/ormconfig.yml", Purpose: "Exposed TypeORM ormconfig.yml"},
	{ID: "typeorm-ormconfig-js", Path: "/ormconfig.js", Purpose: "Exposed TypeORM ormconfig.js"},
	{ID: "dotenv-typeorm-ormconfig-env", Path: "/ormconfig.env", Purpose: "Exposed TypeORM ormconfig.env"},
	{ID: "node-config-default-json", Path: "/config/default.json", Purpose: "Exposed node-config default.json"},
	{ID: "node-config-production-json", Path: "/config/production.json", Purpose: "Exposed node-config production.json"},
	{ID: "node-config-default-yml", Path: "/config/default.yml", Purpose: "Exposed node-config default.yml"},
	{ID: "node-config-local-json", Path: "/config/local.json", Purpose: "Exposed node-config local.json"},
	{ID: "sequelize-config", Path: "/config/config.json", Purpose: "Exposed Sequelize database config"},
	{ID: "knexfile", Path: "/knexfile.js", Purpose: "Exposed Knex knexfile.js"},
	{ID: "prisma-schema", Path: "/prisma/schema.prisma", Purpose: "Exposed Prisma schema"},
	{ID: "pm2-ecosystem", Path: "/ecosystem.config.js", Purpose: "Exposed PM2 ecosystem config"},
	// Next.js framework config is server-side source; it is never meant to be
	// served and leaks rewrites, allowed image hosts, headers and env wiring.
	{ID: "nextjs-config-js", Path: "/next.config.js", Purpose: "Exposed Next.js configuration source"},
	{ID: "nextjs-config-mjs", Path: "/next.config.mjs", Purpose: "Exposed Next.js configuration source"},
	{ID: "nextjs-config-ts", Path: "/next.config.ts", Purpose: "Exposed Next.js configuration source"},
	// Next.js build output served at the web root (a misconfigured static host).
	// None of these are meant to be public: the prerender manifest carries
	// preview-mode signing/encryption keys, and the manifests disclose every
	// route, rewrite, redirect and header rule plus the internal build layout.
	{ID: "nextjs-prerender-manifest", Path: "/.next/prerender-manifest.json", Purpose: "Exposed Next.js prerender manifest"},
	{ID: "nextjs-build-manifest", Path: "/.next/build-manifest.json", Purpose: "Exposed Next.js build manifest"},
	{ID: "nextjs-routes-manifest", Path: "/.next/routes-manifest.json", Purpose: "Exposed Next.js routes manifest"},
	{ID: "nextjs-trace", Path: "/_next/trace", Purpose: "Exposed Next.js build trace"},
	// required-server-files.json embeds the resolved next.config (including
	// env and serverRuntimeConfig values); the server manifests map every route
	// to its server bundle and list Server Action IDs.
	{ID: "nextjs-required-server-files", Path: "/.next/required-server-files.json", Purpose: "Exposed Next.js required-server-files manifest"},
	{ID: "nextjs-server-reference-manifest", Path: "/.next/server/server-reference-manifest.json", Purpose: "Exposed Next.js Server Action manifest"},
	{ID: "nextjs-pages-manifest", Path: "/.next/server/pages-manifest.json", Purpose: "Exposed Next.js pages manifest"},
	{ID: "nextjs-app-paths-manifest", Path: "/.next/server/app-paths-manifest.json", Purpose: "Exposed Next.js app-paths manifest"},
	{ID: "nextjs-middleware-manifest", Path: "/.next/server/middleware-manifest.json", Purpose: "Exposed Next.js middleware manifest"},
	{ID: "nextjs-build-id", Path: "/.next/BUILD_ID", Purpose: "Exposed Next.js build directory"},
	// Container and deployment configuration.
	{ID: "docker-compose", Path: "/docker-compose.yml", Purpose: "Exposed Docker Compose file"},
	{ID: "docker-compose-override", Path: "/docker-compose.override.yml", Purpose: "Exposed Docker Compose override file"},
	{ID: "docker-compose-prod", Path: "/docker-compose.prod.yml", Purpose: "Exposed production Docker Compose file"},
	{ID: "compose-yaml", Path: "/compose.yaml", Purpose: "Exposed Docker Compose file"},
	// Data dumps and directory indexes.
	{ID: "sql-backup", Path: "/backup.sql", Purpose: "Exposed SQL backup"},
	{ID: "sql-database", Path: "/database.sql", Purpose: "Exposed SQL database dump"},
	{ID: "sql-dump", Path: "/dump.sql", Purpose: "Exposed SQL dump"},
	{ID: "ds-store", Path: "/.DS_Store", Purpose: "Exposed macOS directory index"},
	// Lower value: templates (reported only with real values) and CI config.
	{ID: "dotenv-template-example", Path: "/.env.example", Purpose: "Exposed .env.example template"},
	{ID: "dotenv-template-sample", Path: "/.env.sample", Purpose: "Exposed .env.sample template"},
	{ID: "dotenv-template-dist", Path: "/.env.dist", Purpose: "Exposed .env.dist template"},
	{ID: "gitlab-ci", Path: "/.gitlab-ci.yml", Purpose: "Exposed GitLab CI configuration"},
	{ID: "travis-ci", Path: "/.travis.yml", Purpose: "Exposed Travis CI configuration"},
	// NestJS queue dashboards (Bull Board) expose a JSON API that lists, retries
	// and cleans jobs; an unauthenticated one is a real admin surface.
	{ID: "bull-board-admin", Path: "/admin/queues/api/queues", Purpose: "Exposed Bull Board queue dashboard API"},
	{ID: "bull-board-root", Path: "/queues/api/queues", Purpose: "Exposed Bull Board queue dashboard API"},
	{ID: "prometheus-metrics", Path: "/metrics", Purpose: "Exposed Prometheus metrics"},
	{ID: "npm-debug-log", Path: "/npm-debug.log", Purpose: "Exposed npm debug log"},
	{ID: "yarn-error-log", Path: "/yarn-error.log", Purpose: "Exposed Yarn error log"},
	{ID: "vercel-project", Path: "/.vercel/project.json", Purpose: "Exposed Vercel project link"},
	{ID: "nest-cli", Path: "/nest-cli.json", Purpose: "Exposed NestJS CLI project file"},
	{ID: "package-json", Path: "/package.json", Purpose: "Exposed package.json"},
}

var (
	dotenvLine    = regexp.MustCompile(`(?m)^[A-Z_][A-Z0-9_]*=`)
	dotenvKeyLine = regexp.MustCompile(`(?m)^\s*(?:export\s+)?DOTENV_(?:PRIVATE_KEY|KEY|VAULT)[A-Z0-9_]*\s*=\s*\S`)
	gitCredURL    = regexp.MustCompile(`https?://[^/\s]+:[^/@\s]+@`)
	htpasswdEntry = regexp.MustCompile(`(?m)^[^:\s]+:(\$(apr1|2[aby]|1|5|6)\$|\{SHA\}|[A-Za-z0-9./]{13}$)`)
	sqlDumpMarker = regexp.MustCompile(`(?i)(insert into|create table|mysql dump|postgresql database dump|drop table)`)
	// nextConfigShape matches keys that only appear in a Next.js config object,
	// keeping a generic served .js file from being misread as the config.
	nextConfigShape = regexp.MustCompile(`(?i)(nextconfig|reactstrictmode|experimental|\brewrites\b|\bredirects\b|\bimages\s*:|poweredbyheader|output\s*:\s*["']standalone["']|async\s+headers)`)

	railsMasterKey     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	springConfigKey    = regexp.MustCompile(`(?m)^\s*(spring|server|management|logging)[.:]`)
	gcpServiceAccount  = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	dockerAuthEntry    = regexp.MustCompile(`"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"`)
	netrcEntry         = regexp.MustCompile(`(?s)\bmachine\s+\S+.*?\bpassword\s+\S+`)
	pgpassEntry        = regexp.MustCompile(`(?m)^[^:#\s]+:(\d+|\*):[^:\s]+:[^:\s]+:\S+$`)
	iniPasswordLine    = regexp.MustCompile(`(?mi)^\s*password\s*[=:]\s*\S+`)
	kubeconfigShape    = regexp.MustCompile(`(?m)^apiVersion:`)
	gitlabCIShape      = regexp.MustCompile(`(?m)^\s*(stages|image|variables|include)\s*:`)
	ciScriptKey        = regexp.MustCompile(`(?m)^\s*-?\s*script\s*:`)
	travisLanguage     = regexp.MustCompile(`(?m)^language\s*:`)
	configAssignment   = regexp.MustCompile(`^\s*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[=:]\s*(.*)$`)
	jsonStringField    = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_.\-]*)"\s*:\s*"([^"]*)"`)
	jsSingleQuoted     = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'([^']*)'`)
	jsDoubleQuoted     = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"([^"]*)"`)
	xmlKeyValueAttr    = regexp.MustCompile(`(?i)key\s*=\s*"([^"]+)"\s+value\s*=\s*"([^"]*)"`)
	secretNamedKey     = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|private[_\-.]?key|api[_\-.]?key|apikey|access[_\-.]?key|token|connection[_\-.]?string|conn[_\-.]?str|database[_\-.]?url|db[_\-.]?url|\bdsn\b|_dsn|credential|signing[_\-.]?key|encryption[_\-.]?key|master[_\-.]?key)`)
	keyNameUnsafeChars = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)
	nextBuildID        = regexp.MustCompile(`^[A-Za-z0-9_\-]{8,64}$`)
	ormConfigShape     = regexp.MustCompile(`(?i)["']?type["']?\s*[:=]\s*["']?(postgres|mysql|mariadb|mssql|sqlite|better-sqlite3|oracle|mongodb|cockroachdb)`)
	prismaLiteralURL   = regexp.MustCompile(`(?m)^\s*url\s*=\s*"[a-z+]+://[^"\s]*:[^"\s@]+@`)
	promMetricsShape   = regexp.MustCompile(`(?m)^# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* `)
)

// placeholderValues are values a template or sample config uses instead of a
// real secret. Compared lower-case, after trimming quotes.
var placeholderValues = map[string]bool{
	"null": true, "none": true, "nil": true, "true": true, "false": true, "undefined": true,
	"changeme": true, "change-me": true, "change_me": true, "changethis": true, "change-this": true,
	"password": true, "secret": true, "example": true, "sample": true, "placeholder": true,
	"todo": true, "tbd": true, "redacted": true, "dummy": true, "test": true, "default": true,
}

// isPlaceholderValue reports whether a config value is empty, a reference to
// another variable, a template marker or an obvious stand-in, rather than a
// real secret.
func isPlaceholderValue(raw string) bool {
	v := strings.TrimSpace(raw)
	v = strings.TrimSuffix(v, ",")
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	v = strings.TrimSpace(v)
	if len(v) < 3 {
		return true
	}
	lower := strings.ToLower(v)
	if placeholderValues[lower] || isRepeatedChar(v) {
		return true
	}
	for _, prefix := range []string{"your", "<", "$", "%", "{", "[", "|", ">", "#", "//", "env[", "enc["} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, marker := range []string{"${", "{{", "%(", "<%", "xxx", "***", "example.com", "change_me", "changeme", "replace", "insert_", "process.env", "env(", "configservice", "config.get(", "getenv", "os.environ"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isRepeatedChar reports whether v is one character repeated (xxxx, ****).
func isRepeatedChar(v string) bool {
	for i := 1; i < len(v); i++ {
		if v[i] != v[0] {
			return false
		}
	}
	return true
}

// secretKeyNames returns up to 10 names of secret-named keys that carry a
// non-placeholder value, from env/properties/YAML/JSON/XML text. Only the
// key NAMES are returned, sanitized; values never leave this function.
func secretKeyNames(text string) []string {
	var names []string
	seen := map[string]bool{}
	add := func(name, value string) {
		if len(names) >= 10 || !secretNamedKey.MatchString(name) || isPlaceholderValue(value) {
			return
		}
		name = keyNameUnsafeChars.ReplaceAllString(name, "")
		if name == "" || len(name) > 64 || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, line := range strings.Split(text, "\n") {
		if m := jsonStringField.FindAllStringSubmatch(line, -1); len(m) > 0 {
			for _, kv := range m {
				add(kv[1], kv[2])
			}
			continue
		}
		if m := xmlKeyValueAttr.FindAllStringSubmatch(line, -1); len(m) > 0 {
			for _, kv := range m {
				add(kv[1], kv[2])
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		// Inline JavaScript object literals (knexfile, PM2, ormconfig.js):
		// { host: 'db', password: '...' } on one line.
		for _, re := range []*regexp.Regexp{jsSingleQuoted, jsDoubleQuoted} {
			for _, kv := range re.FindAllStringSubmatch(line, -1) {
				add(kv[1], kv[2])
			}
		}
		if m := configAssignment.FindStringSubmatch(line); m != nil {
			value := m[2]
			if i := strings.Index(value, " #"); i >= 0 {
				value = value[:i]
			}
			add(m[1], value)
		}
	}
	return names
}

// providerSecretNames returns the provider names of high-confidence credential
// patterns present in text (never the matched value).
func providerSecretNames(text string) []string {
	var out []string
	for _, rule := range nextjsSecretRules {
		if strings.Contains(text, rule.Prefix) && rule.Pattern.MatchString(text) {
			out = append(out, rule.Provider)
		}
	}
	return dedupeStrings(out)
}

// exposedFileEvidence is redaction-safe evidence: HTTP status, a short shape
// note, secret-named key NAMES and provider rule names. Never values.
func exposedFileEvidence(resp *http.Response, shape string, keyNames, providers []string) string {
	parts := []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
	if shape != "" {
		parts = append(parts, shape)
	}
	if len(keyNames) > 0 {
		parts = append(parts, "secret-named keys with values: "+strings.Join(keyNames, ", "))
	}
	if len(providers) > 0 {
		parts = append(parts, "credential patterns present: "+strings.Join(providers, ", "))
	}
	if len(keyNames) > 0 || len(providers) > 0 {
		parts = append(parts, "values not stored")
	}
	return strings.Join(parts, "; ")
}

// classifyExposedFile confirms each response matches the target file's signature
// before reporting it. The verdict never carries the body: evidence names keys
// and credential types at most, so no secret value or key material is written
// to the findings artifact.
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
	leakWith := func(sev, title, shape string, keys, providers []string) exposureVerdict {
		v := leak(sev, title)
		v.Evidence = exposedFileEvidence(resp, shape, keys, providers)
		return v
	}
	isJSONObject := strings.HasPrefix(text, "{")

	switch {
	case strings.HasPrefix(check.ID, "dotenv-template-"):
		// Templates normally hold placeholders; only real values are a finding.
		if len(dotenvLine.FindAllIndex(trimmed, 2)) < 2 {
			return exposureVerdict{}
		}
		providers := providerSecretNames(text)
		keys := secretKeyNames(text)
		if len(providers) > 0 {
			return leakWith("high", "Example environment file contains real credentials", "", keys, providers)
		}
		if len(keys) > 0 {
			return leakWith("medium", "Example environment file contains secret values", "", keys, nil)
		}
		return exposureVerdict{}
	case strings.HasPrefix(check.ID, "dotenv"):
		if (check.ID == "dotenv-keys" || check.ID == "dotenv-vault") && dotenvKeyLine.Match(trimmed) {
			return leakWith("high", "Exposed dotenv decryption keys", "dotenv key/vault entries present", nil, nil)
		}
		if n := len(dotenvLine.FindAllIndex(trimmed, -1)); n >= 2 {
			return leakWith("high", "Exposed environment file with configuration secrets", fmt.Sprintf("%d variables", n), secretKeyNames(text), providerSecretNames(text))
		}
		return exposureVerdict{}
	}

	switch check.ID {
	case "nextjs-config-js", "nextjs-config-mjs", "nextjs-config-ts":
		// Confirm it is the config module, not an HTML route or 200 catch-all:
		// a module export plus a Next.js config shape marker.
		isModule := strings.Contains(text, "module.exports") || strings.Contains(text, "export default") || strings.Contains(text, "export const")
		hasConfigShape := nextConfigShape.MatchString(lower)
		if isModule && hasConfigShape {
			return leak("medium", "Exposed Next.js configuration source")
		}
	case "nextjs-prerender-manifest":
		// The prerender manifest is JSON; when it carries preview-mode keys their
		// exposure lets anyone enter draft/preview mode. The verdict never includes
		// the body, so no key value is written to the artifact.
		if isJSONObject && strings.Contains(lower, "\"preview\"") &&
			(strings.Contains(lower, "previewmodeid") || strings.Contains(lower, "previewmodesigningkey") || strings.Contains(lower, "previewmodeencryptionkey")) {
			return leak("high", "Exposed Next.js prerender manifest with preview-mode keys")
		}
		if isJSONObject && strings.Contains(lower, "\"version\"") && strings.Contains(lower, "\"routes\"") {
			return leak("medium", "Exposed Next.js prerender manifest")
		}
	case "nextjs-build-manifest":
		if isJSONObject && strings.Contains(lower, "\"pages\"") &&
			(strings.Contains(lower, "\"/_app\"") || strings.Contains(lower, "rootmainfiles") || strings.Contains(lower, "polyfillfiles")) {
			return leak("medium", "Exposed Next.js build manifest")
		}
	case "nextjs-routes-manifest":
		if isJSONObject && strings.Contains(lower, "\"version\"") &&
			(strings.Contains(lower, "dynamicroutes") || strings.Contains(lower, "staticroutes") || strings.Contains(lower, "\"redirects\"") || strings.Contains(lower, "\"rewrites\"")) {
			return leak("medium", "Exposed Next.js routes manifest")
		}
	case "nextjs-trace":
		// The build trace is a JSON array of spans; confirm the shape rather than
		// trust the path alone.
		if strings.HasPrefix(text, "[") && (strings.Contains(lower, "\"traceid\"") || strings.Contains(lower, "\"parentid\"") || strings.Contains(lower, "\"starttime\"")) {
			return leak("low", "Exposed Next.js build trace")
		}
	case "aws-credentials":
		if strings.Contains(lower, "aws_access_key_id") || strings.Contains(lower, "aws_secret_access_key") {
			return leak("high", "Exposed AWS credentials file")
		}
	case "gcp-credentials", "gcp-service-account", "gcp-service-account-key":
		if isJSONObject && gcpServiceAccount.MatchString(text) && strings.Contains(text, `"private_key"`) {
			return leakWith("high", "Exposed Google Cloud service-account key", "service_account JSON with private_key", nil, nil)
		}
	case "kubeconfig", "kubeconfig-root":
		if kubeconfigShape.MatchString(text) && strings.Contains(lower, "clusters:") && strings.Contains(lower, "users:") {
			return leakWith("high", "Exposed Kubernetes kubeconfig", "kubeconfig with clusters and users", nil, nil)
		}
	case "tfstate", "tfstate-backup":
		if isJSONObject && strings.Contains(text, `"terraform_version"`) && strings.Contains(text, `"resources"`) {
			return leakWith("high", "Exposed Terraform state", "terraform state JSON", nil, nil)
		}
	case "docker-config":
		if isJSONObject && strings.Contains(text, `"auths"`) && dockerAuthEntry.MatchString(text) {
			return leakWith("high", "Exposed Docker registry credentials", "docker config with registry auth entries", nil, nil)
		}
	case "git-credentials":
		if gitCredURL.Match(trimmed) {
			return leak("high", "Exposed git credential store")
		}
	case "npmrc":
		if strings.Contains(lower, "_authtoken") || strings.Contains(lower, "_password") || strings.Contains(lower, "registry=") {
			return leak("high", "Exposed npm credentials")
		}
	case "pypirc":
		if (strings.Contains(lower, "[pypi]") || strings.Contains(lower, "[distutils]")) && iniPasswordLine.MatchString(text) {
			return leakWith("high", "Exposed PyPI credentials", "pypirc with password entry", nil, nil)
		}
	case "netrc":
		if netrcEntry.MatchString(text) {
			return leakWith("high", "Exposed .netrc credentials", "netrc machine with password", nil, nil)
		}
	case "pgpass":
		if pgpassEntry.MatchString(text) {
			return leakWith("high", "Exposed PostgreSQL password file", "pgpass host:port:db:user:password entries", nil, nil)
		}
	case "mycnf":
		if (strings.Contains(lower, "[client]") || strings.Contains(lower, "[mysql]") || strings.Contains(lower, "[mysqldump]")) && iniPasswordLine.MatchString(text) {
			return leakWith("high", "Exposed MySQL client credentials", "my.cnf client section with password", nil, nil)
		}
	case "vscode-sftp", "sublime-sftp":
		if isJSONObject && strings.Contains(lower, `"host"`) && (strings.Contains(lower, `"password"`) || strings.Contains(lower, `"privatekeypath"`) || strings.Contains(lower, `"ssh_key_file"`)) {
			return leakWith("high", "Exposed SFTP deployment credentials", "SFTP config with host and credentials", nil, nil)
		}
	case "htpasswd":
		if htpasswdEntry.Match(trimmed) {
			return leak("high", "Exposed htpasswd password hashes")
		}
	case "ssh-key":
		if strings.Contains(text, "-----BEGIN") && strings.Contains(text, "PRIVATE KEY") {
			return leak("high", "Exposed SSH private key")
		}
	case "appsettings", "appsettings-prod", "appsettings-dev":
		if isJSONObject {
			keys := secretKeyNames(text)
			if strings.Contains(lower, `"connectionstrings"`) || len(keys) > 0 {
				return leakWith("high", "Exposed ASP.NET Core appsettings with secrets", "appsettings JSON", keys, providerSecretNames(text))
			}
		}
	case "web-config":
		if strings.Contains(lower, "<configuration") {
			keys := secretKeyNames(text)
			if strings.Contains(lower, "connectionstring=") || (strings.Contains(lower, "<appsettings") && len(keys) > 0) {
				return leakWith("high", "Exposed ASP.NET web.config with secrets", "web.config with connection strings or secret app settings", keys, nil)
			}
		}
	case "spring-props", "spring-yml", "spring-prod-props", "spring-prod-yml":
		if springConfigKey.MatchString(text) {
			keys := secretKeyNames(text)
			if len(keys) > 0 {
				return leakWith("high", "Exposed Spring application configuration with secrets", "Spring Boot configuration", keys, providerSecretNames(text))
			}
			return leakWith("medium", "Exposed Spring application configuration", "Spring Boot configuration", nil, nil)
		}
	case "rails-master-key":
		if railsMasterKey.MatchString(text) {
			return leakWith("high", "Exposed Rails master key", "32-hex-character key file", nil, nil)
		}
	case "rails-secrets-yml":
		if strings.Contains(lower, "secret_key_base") {
			return leakWith("high", "Exposed Rails secrets.yml", "secrets.yml with secret_key_base", secretKeyNames(text), nil)
		}
	case "rails-database-yml":
		if strings.Contains(lower, "adapter:") && strings.Contains(lower, "database:") {
			if keys := secretKeyNames(text); len(keys) > 0 {
				return leakWith("high", "Exposed Rails database configuration with credentials", "database.yml", keys, nil)
			}
			return leakWith("medium", "Exposed Rails database configuration", "database.yml", nil, nil)
		}
	case "config-json", "config-yml", "config-yaml", "settings-json":
		// Generic names: many apps serve a public runtime config here, so only
		// real secret values make this a finding.
		providers := providerSecretNames(text)
		keys := secretKeyNames(text)
		if len(providers) > 0 {
			return leakWith("high", "Exposed configuration file with credentials", "", keys, providers)
		}
		if len(keys) > 0 {
			return leakWith("medium", "Exposed configuration file with secret values", "", keys, nil)
		}
	case "php-config-bak", "wp-config-bak":
		if strings.Contains(lower, "<?php") && (strings.Contains(lower, "password") || strings.Contains(lower, "define(") || strings.Contains(lower, "db_")) {
			return leak("high", "Exposed PHP configuration backup with credentials")
		}
	case "docker-compose", "docker-compose-override", "docker-compose-prod", "compose-yaml":
		if strings.Contains(lower, "services:") && (strings.Contains(lower, "image:") || strings.Contains(lower, "environment:")) {
			return leak("medium", "Exposed Docker Compose configuration")
		}
	case "gitlab-ci", "travis-ci":
		shape := gitlabCIShape.MatchString(text)
		if check.ID == "travis-ci" {
			shape = travisLanguage.MatchString(text)
		}
		if shape && ciScriptKey.MatchString(text) {
			if providers := providerSecretNames(text); len(providers) > 0 {
				return leakWith("medium", "Exposed CI configuration with credentials", "CI pipeline definition", nil, providers)
			}
			return leakWith("low", "Exposed CI configuration", "CI pipeline definition", nil, nil)
		}
	case "nextjs-required-server-files":
		if isJSONObject && strings.Contains(text, `"config"`) && (strings.Contains(text, `"files"`) || strings.Contains(text, `"appDir"`)) {
			keys := secretKeyNames(text)
			providers := providerSecretNames(text)
			if len(keys) > 0 || len(providers) > 0 {
				return leakWith("high", "Exposed Next.js server config with secrets", "required-server-files.json with resolved next.config", keys, providers)
			}
			return leakWith("medium", "Exposed Next.js server config", "required-server-files.json with resolved next.config", nil, nil)
		}
	case "nextjs-server-reference-manifest":
		if isJSONObject && strings.Contains(text, `"node"`) && (strings.Contains(text, `"workers"`) || strings.Contains(text, `"edge"`)) {
			// Next.js stores the Server Actions encryption key in this manifest;
			// with it, closure-bound action arguments can be decrypted and forged.
			if strings.Contains(text, `"encryptionKey"`) {
				return leakWith("high", "Exposed Next.js Server Actions encryption key", "server-reference-manifest.json with encryptionKey", nil, nil)
			}
			return leakWith("medium", "Exposed Next.js Server Action manifest", "Server Action IDs and their modules", nil, nil)
		}
	case "nextjs-pages-manifest":
		if isJSONObject && strings.Contains(text, `"pages/`) && strings.Contains(text, `.js"`) {
			return leakWith("medium", "Exposed Next.js pages manifest", "route to server-bundle map", nil, nil)
		}
	case "nextjs-app-paths-manifest":
		if isJSONObject && strings.Contains(text, `"app/`) && (strings.Contains(text, `/page"`) || strings.Contains(text, `/route"`) || strings.Contains(text, `/page.js"`) || strings.Contains(text, `/route.js"`)) {
			return leakWith("medium", "Exposed Next.js app-paths manifest", "app route to server-bundle map", nil, nil)
		}
	case "nextjs-middleware-manifest":
		if isJSONObject && strings.Contains(text, `"middleware"`) && strings.Contains(text, `"version"`) {
			return leakWith("medium", "Exposed Next.js middleware manifest", "middleware matchers", nil, nil)
		}
	case "nextjs-build-id":
		// Build IDs are random (nanoid) or a git hash; requiring a digit keeps a
		// plain-text "Unauthorized"/"Forbidden" body from matching.
		if len(text) >= 10 && nextBuildID.MatchString(text) && strings.ContainsAny(text, "0123456789") {
			return leakWith("low", "Exposed Next.js build directory", ".next/BUILD_ID served", nil, nil)
		}
	case "vercel-project":
		if isJSONObject && strings.Contains(text, `"projectId"`) && strings.Contains(text, `"orgId"`) {
			return leakWith("low", "Exposed Vercel project link", "project and org IDs", nil, nil)
		}
	case "typeorm-ormconfig-json", "typeorm-ormconfig-yml", "typeorm-ormconfig-js":
		if ormConfigShape.MatchString(text) && (strings.Contains(lower, "database") || strings.Contains(lower, "host") || strings.Contains(lower, "url")) {
			if keys := secretKeyNames(text); len(keys) > 0 {
				return leakWith("high", "Exposed TypeORM configuration with database credentials", "TypeORM connection options", keys, nil)
			}
			return leakWith("medium", "Exposed TypeORM configuration", "TypeORM connection options", nil, nil)
		}
	case "sequelize-config":
		if isJSONObject && strings.Contains(text, `"dialect"`) && (strings.Contains(text, `"development"`) || strings.Contains(text, `"production"`)) {
			if keys := secretKeyNames(text); len(keys) > 0 {
				return leakWith("high", "Exposed Sequelize configuration with database credentials", "Sequelize environments", keys, nil)
			}
			return leakWith("medium", "Exposed Sequelize configuration", "Sequelize environments", nil, nil)
		}
	case "knexfile":
		if strings.Contains(text, "module.exports") && strings.Contains(lower, "client") && strings.Contains(lower, "connection") {
			if keys := secretKeyNames(text); len(keys) > 0 {
				return leakWith("high", "Exposed Knex configuration with database credentials", "knexfile connection", keys, nil)
			}
			return leakWith("medium", "Exposed Knex configuration", "knexfile connection", nil, nil)
		}
	case "prisma-schema":
		if strings.Contains(text, "datasource") && strings.Contains(text, "provider") {
			if prismaLiteralURL.MatchString(text) {
				return leakWith("high", "Exposed Prisma schema with a hard-coded database URL", "datasource url with credentials", nil, nil)
			}
			return leakWith("medium", "Exposed Prisma schema", "datasource and data model", nil, nil)
		}
	case "pm2-ecosystem":
		if strings.Contains(text, "apps") && strings.Contains(lower, "script") && (strings.Contains(text, "module.exports") || strings.Contains(text, "export default")) {
			keys := secretKeyNames(text)
			providers := providerSecretNames(text)
			if len(keys) > 0 || len(providers) > 0 {
				return leakWith("high", "Exposed PM2 ecosystem config with secrets", "PM2 apps and env", keys, providers)
			}
			return leakWith("medium", "Exposed PM2 ecosystem config", "PM2 apps and env", nil, nil)
		}
	case "node-config-default-json", "node-config-production-json", "node-config-default-yml", "node-config-local-json":
		providers := providerSecretNames(text)
		keys := secretKeyNames(text)
		if len(providers) > 0 {
			return leakWith("high", "Exposed application config with credentials", "node-config file", keys, providers)
		}
		if len(keys) > 0 {
			return leakWith("high", "Exposed application config with secret values", "node-config file", keys, nil)
		}
	case "bull-board-admin", "bull-board-root":
		if isJSONObject && strings.Contains(text, `"queues"`) && (strings.Contains(text, `"counts"`) || strings.Contains(text, `"jobs"`)) {
			return leakWith("high", "Unauthenticated Bull Board queue dashboard", "queue list with job counts", nil, nil)
		}
	case "prometheus-metrics":
		if promMetricsShape.MatchString(text) {
			return leakWith("low", "Exposed Prometheus metrics endpoint", "Prometheus exposition format", nil, nil)
		}
	case "npm-debug-log", "yarn-error-log":
		if strings.Contains(text, "npm ERR!") || strings.Contains(text, "verbose cli") || (strings.Contains(text, "Arguments:") && strings.Contains(text, "PATH:")) || strings.Contains(text, "Yarn version:") {
			return leakWith("medium", "Exposed package-manager error log", "npm/yarn log with environment details", nil, nil)
		}
	case "nest-cli":
		if isJSONObject && (strings.Contains(text, "@nestjs/schematics") || (strings.Contains(text, `"sourceRoot"`) && strings.Contains(text, `"compilerOptions"`))) {
			return leakWith("low", "Exposed NestJS CLI project file", "nest-cli.json", nil, nil)
		}
	case "package-json":
		if isJSONObject && strings.Contains(text, `"name"`) && (strings.Contains(text, `"dependencies"`) || strings.Contains(text, `"devDependencies"`)) {
			return leakWith("low", "Exposed package.json", "dependency and script manifest", nil, nil)
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

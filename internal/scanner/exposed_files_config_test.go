package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/acho2003/pent-tool/internal/assessment"
)

// Planted secret values. None may ever appear in a verdict or artifact.
const (
	plantedPassword = "S3cr3tPassw0rd-planted"
	plantedToken    = "tok-9f8e7d6c5b4a-planted"
	plantedAWS      = "AKIAZZZZZZZZZZZZZZZZ"
)

type exposedFileCase struct {
	id, body, contentType string
	wantSeverity          string // "" = must not be reported
	wantKeyName           string // optional key name expected in evidence
}

func exposedFileCases() []exposedFileCase {
	return []exposedFileCase{
		// Env family from the operator's list and common extras.
		{id: "dotenv-staging", body: "APP_ENV=staging\nDB_PASSWORD=" + plantedPassword + "\n", wantSeverity: "high", wantKeyName: "DB_PASSWORD"},
		{id: "dotenv-prod-bak", body: "NODE_ENV=production\nJWT_SECRET=" + plantedToken + "\n", wantSeverity: "high", wantKeyName: "JWT_SECRET"},
		{id: "dotenv-docker", body: "POSTGRES_USER=app\nPOSTGRES_PASSWORD=" + plantedPassword + "\n", wantSeverity: "high"},
		{id: "dotenv-tilde", body: "ONLY_ONE=line\n", wantSeverity: ""},
		{id: "dotenv-keys", body: "#/ dotenvx keys\nDOTENV_PRIVATE_KEY_PRODUCTION=" + plantedToken + "\n", wantSeverity: "high"},
		{id: "dotenv-vault", body: "DOTENV_VAULT_PRODUCTION=\"" + plantedToken + "\"\n", wantSeverity: "high"},
		// Templates: placeholders are normal, real values are not.
		{id: "dotenv-template-example", body: "DB_HOST=localhost\nDB_PASSWORD=changeme\nAPI_KEY=your_api_key_here\nSECRET=${SECRET}\n", wantSeverity: ""},
		{id: "dotenv-template-example", body: "DB_HOST=localhost\nDB_PASSWORD=" + plantedPassword + "\n", wantSeverity: "medium", wantKeyName: "DB_PASSWORD"},
		{id: "dotenv-template-sample", body: "AWS_REGION=us-east-1\nAWS_ACCESS_KEY_ID=" + plantedAWS + "\n", wantSeverity: "high"},
		// Cloud and infrastructure credentials.
		{id: "gcp-service-account", body: `{"type": "service_account", "project_id": "p", "private_key": "-----BEGIN PRIVATE KEY-----` + plantedToken + `"}`, wantSeverity: "high"},
		{id: "gcp-credentials", body: `{"installed": {"client_id": "x"}}`, wantSeverity: ""},
		{id: "kubeconfig", body: "apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s\nusers:\n- name: admin\n  user:\n    token: " + plantedToken + "\n", wantSeverity: "high"},
		{id: "tfstate", body: `{"version": 4, "terraform_version": "1.6.0", "resources": [{"instances": [{"attributes": {"password": "` + plantedPassword + `"}}]}]}`, wantSeverity: "high"},
		{id: "tfstate", body: `{"version": 4, "resources": []}`, wantSeverity: ""},
		{id: "docker-config", body: `{"auths": {"registry.example": {"auth": "dXNlcjpTM2NyM3RQYXNzdzByZA=="}}}`, wantSeverity: "high"},
		{id: "docker-config", body: `{"auths": {"registry.example": {}}, "credsStore": "desktop"}`, wantSeverity: ""},
		{id: "netrc", body: "machine api.example.com\n  login deploy\n  password " + plantedPassword + "\n", wantSeverity: "high"},
		{id: "pgpass", body: "db.internal:5432:app:app_user:" + plantedPassword + "\n", wantSeverity: "high"},
		{id: "mycnf", body: "[client]\nuser=root\npassword=" + plantedPassword + "\n", wantSeverity: "high"},
		{id: "mycnf", body: "[mysqld]\nport=3306\n", wantSeverity: ""},
		{id: "pypirc", body: "[pypi]\nusername = __token__\npassword = " + plantedToken + "\n", wantSeverity: "high"},
		{id: "vscode-sftp", body: `{"name": "prod", "host": "10.0.0.5", "username": "deploy", "password": "` + plantedPassword + `"}`, wantSeverity: "high"},
		// Application configuration.
		{id: "appsettings-prod", body: `{"ConnectionStrings": {"Default": "Server=db;Password=` + plantedPassword + `"}, "Logging": {}}`, wantSeverity: "high"},
		{id: "appsettings", body: `{"Logging": {"LogLevel": {"Default": "Information"}}, "AllowedHosts": "*"}`, wantSeverity: ""},
		{id: "web-config", contentType: "application/xml", body: `<?xml version="1.0"?><configuration><connectionStrings><add name="db" connectionString="Server=db;Password=` + plantedPassword + `"/></connectionStrings></configuration>`, wantSeverity: "high"},
		{id: "web-config", contentType: "application/xml", body: `<?xml version="1.0"?><configuration><system.web><compilation debug="false"/></system.web></configuration>`, wantSeverity: ""},
		{id: "spring-props", body: "spring.datasource.url=jdbc:postgresql://db/app\nspring.datasource.password=" + plantedPassword + "\n", wantSeverity: "high", wantKeyName: "spring.datasource.password"},
		{id: "spring-yml", body: "server:\n  port: 8080\nlogging:\n  level: INFO\n", wantSeverity: "medium"},
		{id: "spring-yml", body: "name: not-spring\nport: 8080\n", wantSeverity: ""},
		{id: "rails-master-key", body: "0123456789abcdef0123456789abcdef", wantSeverity: "high"},
		{id: "rails-master-key", body: "not-a-key-but-exactly-32-chars!!", wantSeverity: ""},
		{id: "rails-secrets-yml", body: "production:\n  secret_key_base: " + plantedToken + "\n", wantSeverity: "high"},
		{id: "rails-database-yml", body: "production:\n  adapter: postgresql\n  database: app\n  password: <%= ENV['DB_PASSWORD'] %>\n", wantSeverity: "medium"},
		{id: "rails-database-yml", body: "production:\n  adapter: postgresql\n  database: app\n  password: " + plantedPassword + "\n", wantSeverity: "high"},
		// Generic config names are value-gated: a public runtime config is fine.
		{id: "config-json", body: `{"apiBaseUrl": "https://api.example.test", "featureFlags": {"beta": true}}`, wantSeverity: ""},
		{id: "config-json", body: `{"apiBaseUrl": "https://api.example.test", "clientSecret": "` + plantedToken + `"}`, wantSeverity: "medium", wantKeyName: "clientSecret"},
		{id: "config-yml", body: "aws:\n  access_key_id: " + plantedAWS + "\n", wantSeverity: "high"},
		{id: "docker-compose-prod", body: "services:\n  db:\n    image: postgres:16\n", wantSeverity: "medium"},
		{id: "gitlab-ci", body: "stages:\n  - test\ntest:\n  script:\n    - go test ./...\n", wantSeverity: "low"},
		{id: "travis-ci", body: "language: go\nscript: go test ./...\n", wantSeverity: "low"},
		// Next.js / Vercel build and deployment files.
		{id: "dotenv-vercel-production", body: "# Created by Vercel CLI\nNEXTAUTH_SECRET=\"" + plantedToken + "\"\nDATABASE_URL=\"postgres://u:" + plantedPassword + "@db/app\"\n", wantSeverity: "high", wantKeyName: "NEXTAUTH_SECRET"},
		{id: "nextjs-required-server-files", body: `{"version":1,"config":{"env":{"INTERNAL_API_TOKEN":"` + plantedToken + `"},"serverRuntimeConfig":{}},"appDir":"/app","files":[".next/routes-manifest.json"]}`, wantSeverity: "high", wantKeyName: "INTERNAL_API_TOKEN"},
		{id: "nextjs-required-server-files", body: `{"version":1,"config":{"images":{"domains":[]}},"appDir":"/app","files":[]}`, wantSeverity: "medium"},
		{id: "nextjs-server-reference-manifest", body: `{"node":{"7f3a":{"workers":{"app/page":"x"},"layer":{}}},"edge":{},"encryptionKey":"` + plantedToken + `"}`, wantSeverity: "high"},
		{id: "nextjs-server-reference-manifest", body: `{"node":{"7f3a":{"workers":{"app/page":"x"}}},"edge":{}}`, wantSeverity: "medium"},
		{id: "nextjs-pages-manifest", body: `{"/_app":"pages/_app.js","/api/users":"pages/api/users.js"}`, wantSeverity: "medium"},
		{id: "nextjs-app-paths-manifest", body: `{"/page":"app/page.js","/api/orders/route":"app/api/orders/route.js"}`, wantSeverity: "medium"},
		{id: "nextjs-middleware-manifest", body: `{"version":3,"middleware":{"/":{"matchers":[{"regexp":"^/admin"}]}},"functions":{}}`, wantSeverity: "medium"},
		{id: "nextjs-build-id", body: "Xy1_aB3cD4eF5gH6iJ7kL", wantSeverity: "low"},
		{id: "nextjs-build-id", body: "Unauthorized", wantSeverity: ""},
		{id: "nextjs-build-id", body: "not a build id at all", wantSeverity: ""},
		{id: "vercel-project", body: `{"projectId":"prj_abc","orgId":"team_xyz"}`, wantSeverity: "low"},
		// NestJS / Node.js config, ORM, logs, dashboards.
		{id: "typeorm-ormconfig-json", body: `{"type": "postgres", "host": "db", "username": "app", "password": "` + plantedPassword + `", "database": "app", "synchronize": false}`, wantSeverity: "high", wantKeyName: "password"},
		{id: "typeorm-ormconfig-js", body: "module.exports = {\n  type: 'postgres',\n  host: process.env.DB_HOST,\n  password: process.env.DB_PASSWORD,\n  database: 'app',\n};\n", wantSeverity: "medium"},
		{id: "typeorm-ormconfig-json", body: `{"name": "not-an-orm"}`, wantSeverity: ""},
		{id: "dotenv-typeorm-ormconfig-env", body: "TYPEORM_CONNECTION=postgres\nTYPEORM_PASSWORD=" + plantedPassword + "\n", wantSeverity: "high"},
		{id: "node-config-production-json", body: `{"jwt": {"secret": "` + plantedToken + `"}, "port": 3000}`, wantSeverity: "high", wantKeyName: "secret"},
		{id: "node-config-default-json", body: `{"port": 3000, "jwt": {"secret": "${JWT_SECRET}"}}`, wantSeverity: ""},
		{id: "sequelize-config", body: `{"development": {"username": "root", "password": "` + plantedPassword + `", "database": "app", "dialect": "mysql"}}`, wantSeverity: "high"},
		{id: "knexfile", body: "module.exports = {\n  client: 'pg',\n  connection: { host: 'db', password: '" + plantedPassword + "' },\n};\n", wantSeverity: "high"},
		{id: "prisma-schema", body: "datasource db {\n  provider = \"postgresql\"\n  url      = env(\"DATABASE_URL\")\n}\nmodel User { id Int @id }\n", wantSeverity: "medium"},
		{id: "prisma-schema", body: "datasource db {\n  provider = \"postgresql\"\n  url      = \"postgresql://app:" + plantedPassword + "@db:5432/app\"\n}\n", wantSeverity: "high"},
		{id: "pm2-ecosystem", body: "module.exports = {\n  apps: [{ name: 'api', script: 'dist/main.js', env: { JWT_SECRET: '" + plantedToken + "' } }],\n};\n", wantSeverity: "high", wantKeyName: "JWT_SECRET"},
		{id: "bull-board-admin", body: `{"queues":[{"name":"email","counts":{"active":0,"failed":3},"jobs":[]}]}`, wantSeverity: "high"},
		{id: "bull-board-root", body: `{"queues": "disabled"}`, wantSeverity: ""},
		{id: "prometheus-metrics", body: "# HELP process_cpu_user_seconds_total Total user CPU time.\n# TYPE process_cpu_user_seconds_total counter\nprocess_cpu_user_seconds_total 1.2\n", wantSeverity: "low"},
		{id: "prometheus-metrics", body: "ok", wantSeverity: ""},
		{id: "npm-debug-log", body: "0 info it worked if it ends with ok\n1 verbose cli [ '/usr/bin/node' ]\n2 npm ERR! code ELIFECYCLE\n", wantSeverity: "medium"},
		{id: "nest-cli", body: `{"$schema":"https://json.schemastore.org/nest-cli","collection":"@nestjs/schematics","sourceRoot":"src"}`, wantSeverity: "low"},
		{id: "package-json", body: `{"name":"api","version":"1.0.0","dependencies":{"@nestjs/core":"10.0.0"}}`, wantSeverity: "low"},
		{id: "package-json", body: `{"name":"public-manifest","short_name":"app"}`, wantSeverity: ""},
	}
}

func TestExposedFilesConfigClassifierPositivesAndNearMisses(t *testing.T) {
	catalog := map[string]bool{}
	for _, c := range exposedFilesCatalog {
		catalog[c.ID] = true
	}
	for _, tc := range exposedFileCases() {
		if !catalog[tc.id] {
			t.Fatalf("test case %q is not in the catalog", tc.id)
		}
		header := http.Header{}
		ct := tc.contentType
		if ct == "" {
			ct = "text/plain"
		}
		header.Set("Content-Type", ct)
		v := classifyExposedFile(exposureCheck{ID: tc.id}, &http.Response{StatusCode: 200, Header: header}, []byte(tc.body))
		if v.Severity != tc.wantSeverity {
			t.Errorf("%s: severity=%q want %q (verdict %+v) body=%q", tc.id, v.Severity, tc.wantSeverity, v, tc.body)
			continue
		}
		if tc.wantKeyName != "" && !strings.Contains(v.Evidence, tc.wantKeyName) {
			t.Errorf("%s: evidence %q lacks key name %q", tc.id, v.Evidence, tc.wantKeyName)
		}
		for _, secret := range []string{plantedPassword, plantedToken, plantedAWS} {
			if strings.Contains(v.Evidence, secret) || strings.Contains(v.Title, secret) {
				t.Errorf("%s: secret value leaked into verdict: %+v", tc.id, v)
			}
		}
		// The same body served as an HTML catch-all is never a finding.
		htmlHeader := http.Header{}
		htmlHeader.Set("Content-Type", "text/html")
		if hv := classifyExposedFile(exposureCheck{ID: tc.id}, &http.Response{StatusCode: 200, Header: htmlHeader}, []byte(tc.body)); hv.Classification != "" {
			t.Errorf("%s: HTML response reported: %+v", tc.id, hv)
		}
		if nv := classifyExposedFile(exposureCheck{ID: tc.id}, &http.Response{StatusCode: 404, Header: header}, []byte(tc.body)); nv.Classification != "" {
			t.Errorf("%s: 404 response reported: %+v", tc.id, nv)
		}
	}
}

func TestExposedFilesCatalogCoversOperatorEnvList(t *testing.T) {
	paths := map[string]bool{}
	for _, c := range exposedFilesCatalog {
		paths[c.Path] = true
	}
	for _, p := range []string{"/.env.development.local", "/.env.docker", "/.env.keys", "/.env.monorepo", "/.env.preprod", "/.env.prod.bak", "/.env.production.local", "/.env.secret", "/.env.shared", "/.env.staging"} {
		if !paths[p] {
			t.Errorf("catalog is missing %s", p)
		}
	}
}

func TestIsPlaceholderValue(t *testing.T) {
	for _, v := range []string{"process.env.DB_PASSWORD,", "env(\"DATABASE_URL\")", "configService.get('JWT_SECRET')", "", "  ", "changeme", "\"\"", "${DB_PASSWORD}", "<your-password>", "your_api_key", "xxxxxxxx", "******", "null", "<%= ENV['X'] %>", "{{ .Values.pw }}", "ab"} {
		if !isPlaceholderValue(v) {
			t.Errorf("%q should be a placeholder", v)
		}
	}
	for _, v := range []string{plantedPassword, "\"" + plantedToken + "\",", "hunter22"} {
		if isPlaceholderValue(v) {
			t.Errorf("%q should be a real value", v)
		}
	}
}

// End to end through the shared driver on a path-scoped target: every request
// is a GET inside the approved path, new files are found, and the artifact
// carries key names but no planted value.
func TestExposedFilesConfigEndToEndNoLeak(t *testing.T) {
	served := map[string]string{
		"/svc/app/.env.staging":                "APP_ENV=staging\nDB_PASSWORD=" + plantedPassword + "\n",
		"/svc/app/.env.keys":                   "DOTENV_PRIVATE_KEY_PRODUCTION=" + plantedToken + "\n",
		"/svc/app/appsettings.Production.json": `{"ConnectionStrings": {"Default": "Password=` + plantedPassword + `"}}`,
		"/svc/app/.kube/config":                "apiVersion: v1\nclusters: []\nusers:\n- user:\n    token: " + plantedToken + "\n",
		"/svc/app/config.json":                 `{"apiBaseUrl": "https://public.example.test"}`,
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if body, ok := served[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	target := server.URL + "/svc/app"
	cfg := assessment.AssessmentConfig{Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: target}}}
	scope := assessment.AppScopeForTarget(cfg, "app")
	run := (exposedFilesRunner{}).Run(context.Background(), Request{Target: target, ScanDir: t.TempDir(), Scope: "assessment:app", TypedAssessment: true, AppScope: &scope}, Config{Budget: NewAssessmentBudget(0, 500, 0)}, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%q reason=%q", run.Status, run.Reason)
	}
	if len(requests) != len(exposedFilesCatalog) {
		t.Fatalf("expected one request per catalog entry (%d), got %d", len(exposedFilesCatalog), len(requests))
	}
	for _, got := range requests {
		if !strings.HasPrefix(got, "GET /svc/app/") {
			t.Fatalf("request was not a GET inside the approved path: %s", got)
		}
	}
	data, err := os.ReadFile(run.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if got := strings.Count(text, "sensitive_file_exposed"); got != 4 {
		t.Fatalf("expected 4 findings (.env.staging, .env.keys, appsettings, kubeconfig), got %d: %s", got, text)
	}
	if !strings.Contains(text, "DB_PASSWORD") {
		t.Fatalf("evidence should name the secret key: %s", text)
	}
	for _, secret := range []string{plantedPassword, plantedToken} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret value leaked into the artifact: %q", secret)
		}
	}
}

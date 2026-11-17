package scanner

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

//go:embed rules/nestjs.yaml
var nestjsSASTRules []byte

const nestjsSASTVersion = "nestjs-sast-v1"

type nestjsSASTRunner struct{}

func (nestjsSASTRunner) Name() string { return "nestjs-sast" }
func (nestjsSASTRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nestjs-sast", Summary: "Offline NestJS configuration, authorization and local request-to-sink source checks", Phase: PhaseSAST, Applies: appliesToSource, Weight: WeightLight}
}

const nestjsRouteWithoutGuard = "nestjs-route-without-guard"

var nestjsSASTCatalog = map[string]sastRule{
	"nestjs-sql-raw-query-interpolation":       {"Raw SQL built from interpolated values", "high", "CWE-89", "local_pattern", "Pass values as bound parameters (query(sql, [values]), where('col = :v', { v })) and allow-list identifiers such as sort columns."},
	"nestjs-prisma-raw-unsafe":                 {"Prisma raw Unsafe query with a non-constant SQL string", "high", "CWE-89", "local_pattern", "Use the $queryRaw / $executeRaw tagged templates, which bind interpolated values, instead of the Unsafe variants."},
	"nestjs-typeorm-synchronize-enabled":       {"TypeORM schema synchronize enabled", "medium", "CWE-1188", "static_configuration", "Disable synchronize outside local development and apply schema changes with reviewed migrations."},
	"nestjs-validation-pipe-without-whitelist": {"ValidationPipe without whitelist (mass assignment)", "medium", "CWE-915", "static_configuration", "Use new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }) so undeclared DTO properties are stripped or rejected."},
	"nestjs-jwt-ignore-expiration":             {"JWT expiration ignored", "high", "CWE-613", "static_configuration", "Set ignoreExpiration: false (the default) so expired tokens are rejected."},
	"nestjs-jwt-hardcoded-secret":              {"Hard-coded JWT secret or literal fallback", "high", "CWE-798", "static_configuration", "Load the signing secret from configuration or a secret store with no literal fallback, and rotate any secret that was committed."},
	"nestjs-cors-credentials-any-origin":       {"CORS allows credentials from any origin", "medium", "CWE-942", "static_configuration", "Allow-list the exact trusted origins when credentials: true is required."},
	"nestjs-swagger-unconditional":             {"Swagger UI mounted unconditionally", "low", "CWE-200", "static_configuration", "Mount SwaggerModule only outside production, or protect the documentation route with authentication."},
	nestjsRouteWithoutGuard:                    {"Route handler without an authorization guard", "low", "CWE-862", "heuristic", "Confirm the route is meant to be public; otherwise add @UseGuards on the method or controller, or register a global guard and mark public routes explicitly."},
	"nestjs-request-to-ssrf":                   {"Request-controlled server-side fetch destination", "high", "CWE-918", "local_dataflow", "Map request values to an allow-list of destinations and block internal addresses and redirects before fetching."},
	"nestjs-request-to-redirect":               {"Request-controlled redirect destination", "medium", "CWE-601", "local_dataflow", "Only redirect to local paths or an allow-list of destinations."},
	"nestjs-request-to-file-path":              {"Request-controlled filesystem path", "high", "CWE-22", "local_dataflow", "Resolve the path against a fixed base, reject traversal (basename or a resolved-prefix check), and prefer IDs over file names."},
	"nestjs-request-to-command":                {"Request-controlled shell command", "critical", "CWE-78", "local_dataflow", "Do not build shell commands from request values; use execFile/spawn with an argument array and an allow-list."},
}

// nestjsSASTTarget selects TypeScript and JavaScript sources, leaving out type
// declarations and test files.
func nestjsSASTTarget(path string) bool {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != ".ts" && ext != ".js" && ext != ".mts" && ext != ".cts" {
		return false
	}
	for _, suffix := range []string{".d.ts", ".spec.ts", ".test.ts", ".e2e-spec.ts", ".spec.js", ".test.js"} {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	return true
}

func nestjsSASTSkipDir(name string) bool {
	switch name {
	case "test", "tests", "__tests__", "e2e", "__mocks__":
		return true
	}
	return false
}

// nestjsGlobalGuardMarkers mean the project registers a guard for every route,
// so a handler without its own @UseGuards is still protected.
var nestjsGlobalGuardMarkers = [][]byte{[]byte("APP_GUARD"), []byte("useGlobalGuards(")}

// nestjsDropGuardedRoutes removes route-without-guard findings when any
// snapshot file registers a global guard. The snapshot holds only selected
// files, so app.module.ts and main.ts are both in it.
func nestjsDropGuardedRoutes(snapshot string, files []sastFile, findings []Finding) []Finding {
	global := false
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(snapshot, filepath.FromSlash(file.Path)))
		if err != nil {
			continue
		}
		for _, marker := range nestjsGlobalGuardMarkers {
			if bytes.Contains(body, marker) {
				global = true
				break
			}
		}
		if global {
			break
		}
	}
	if !global {
		return findings
	}
	kept := findings[:0]
	for _, finding := range findings {
		if finding.RuleID != nestjsRouteWithoutGuard {
			kept = append(kept, finding)
		}
	}
	return kept
}

var nestjsSASTSpec = bundledSASTSpec{
	Scanner: "nestjs-sast", Framework: "NestJS", Version: nestjsSASTVersion, Rules: nestjsSASTRules, Catalog: nestjsSASTCatalog,
	IsTarget: nestjsSASTTarget,
	DetectPackage: func(deps map[string]json.RawMessage) bool {
		return deps["@nestjs/core"] != nil || deps["@nestjs/common"] != nil
	},
	SkipDir:     nestjsSASTSkipDir,
	Postprocess: nestjsDropGuardedRoutes,
}

func (nestjsSASTRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runBundledSAST(ctx, nestjsSASTSpec, req, cfg, emit)
}

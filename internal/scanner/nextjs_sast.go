package scanner

import (
	"context"
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
)

//go:embed rules/nextjs.yaml
var nextjsSASTRules []byte

const nextjsSASTVersion = "nextjs-sast-v2"
const nextjsSASTMaxFile = bundledSASTMaxFile

type nextjsSASTRunner struct{}

func (nextjsSASTRunner) Name() string { return "nextjs-sast" }
func (nextjsSASTRunner) Descriptor() Descriptor {
	return Descriptor{Name: "nextjs-sast", Summary: "Offline Next.js configuration and local request-to-sink source checks", Phase: PhaseSAST, Applies: appliesToSource, Weight: WeightLight}
}

type nextjsSASTFile = sastFile
type nextjsSASTManifest = sastManifest
type nextjsSASTRule = sastRule

func nextjsSASTConfig(name string) bool {
	return name == "next.config.js" || name == "next.config.mjs" || name == "next.config.cjs" || name == "next.config.ts"
}
func nextjsSASTTarget(name string) bool {
	base := filepath.Base(name)
	if nextjsSASTConfig(base) {
		return true
	}
	path := "/" + filepath.ToSlash(name)
	if strings.Contains(path, "/app/") && (base == "route.js" || base == "route.ts") {
		return true
	}
	ext := filepath.Ext(name)
	return strings.Contains(path, "/pages/api/") && (ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs")
}

var nextjsSASTCatalog = map[string]sastRule{
	"nextjs-config-private-env-inline":      {"Potential private value exported through Next.js env configuration", "medium", "CWE-200", "static_configuration", "Keep private values out of next.config env; use server-only environment access and minimal response data."},
	"nextjs-config-local-image-fetch":       {"Local-IP image optimization enabled", "low", "CWE-918", "static_configuration", "Review whether local-IP image optimization is required and constrain fetch destinations and redirects."},
	"nextjs-config-wildcard-action-origins": {"Global wildcard in Server Action origin configuration", "medium", "CWE-346", "static_configuration", "Use explicit intended Server Action origins and verify the deployed framework's origin behavior."},
	"nextjs-route-query-redirect":           {"Request-derived redirect destination in a Next.js handler", "medium", "CWE-601", "local_dataflow", "Normalize redirect destinations and enforce an explicit local-path or destination allowlist."},
	"nextjs-route-body-fetch":               {"Request-body-derived server-side fetch destination in a Next.js handler", "medium", "CWE-918", "local_dataflow", "Map incoming body values to explicit allowed destinations and enforce redirect and network policies before server-side fetching."},
	"nextjs-route-body-redirect":            {"Request-body-derived redirect destination in a Next.js handler", "medium", "CWE-601", "local_dataflow", "Map incoming body values to explicit allowed local routes or approved redirect destinations."},
	"nextjs-route-query-fetch":              {"Request-derived server-side fetch destination in a Next.js handler", "medium", "CWE-918", "local_dataflow", "Enforce destination and redirect allowlists before server-side fetching, then verify the policy with a controlled callback."},
	"nextjs-route-private-env-response":     {"Potential private environment value serialized to a response", "medium", "CWE-200", "local_dataflow", "Return minimal authorized data and keep private environment values out of response serialization."},
}

var nextjsSASTSpec = bundledSASTSpec{
	Scanner: "nextjs-sast", Framework: "Next.js", Version: nextjsSASTVersion, Rules: nextjsSASTRules, Catalog: nextjsSASTCatalog,
	IsTarget:   nextjsSASTTarget,
	DetectFile: func(path string) bool { return nextjsSASTConfig(filepath.Base(path)) },
	DetectPackage: func(deps map[string]json.RawMessage) bool {
		return deps["next"] != nil
	},
}

func snapshotNextjsSAST(ctx context.Context, source, destination string) (sastManifest, error) {
	return snapshotBundledSAST(ctx, nextjsSASTSpec, source, destination)
}

func normalizeNextjsSAST(raw []byte, snapshot, evidence string, files []sastFile) ([]Finding, int, int, error) {
	return normalizeBundledSAST(nextjsSASTSpec, raw, snapshot, evidence, files)
}

func (nextjsSASTRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runBundledSAST(ctx, nextjsSASTSpec, req, cfg, emit)
}

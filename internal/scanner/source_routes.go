package scanner

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Source route extraction reads an operator-supplied source tree (a White Box
// repository or local path linked to a URL target with related_to) and lists
// the HTTP routes the code declares: NestJS controllers and Next.js app/pages
// routes. The routes seed the URL target's request inventory exactly like an
// uploaded OpenAPI definition does, so live scanners test endpoints the crawler
// never reached. Nothing is executed; files are read with the same bounds as
// the bundled source checks, and route paths are only ever resolved against
// the already approved target URL and re-checked against its scope.

const sourceRoutesTool = "source-routes"

// SourceRoute is one HTTP route declared in source.
type SourceRoute struct {
	Framework string             `json:"framework"`
	Method    string             `json:"method"`
	Path      string             `json:"path"` // "/users/{id}", parameters in braces
	File      string             `json:"file"`
	Line      int                `json:"line"`
	Handler   string             `json:"handler,omitempty"`
	Query     []sourceRouteParam `json:"query,omitempty"`
}

type sourceRouteParam struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

type sourcePackage struct {
	nest, next     bool
	globalPrefix   string
	uriVersioning  bool
	defaultVersion string
	nextBasePath   string
}

var sourceRouteSkipDirs = map[string]bool{"node_modules": true, ".git": true, ".next": true, "out": true, "dist": true, "build": true, "coverage": true, "vendor": true, "test": true, "tests": true, "__tests__": true, "e2e": true, "__mocks__": true}

// ExtractSourceRoutes walks root (bounded, no symlinks) and returns the
// declared routes, sorted, plus human-readable gaps.
func ExtractSourceRoutes(ctx context.Context, root string) ([]SourceRoute, []string) {
	files, gaps := readSourceRouteFiles(ctx, root)
	packages := map[string]*sourcePackage{}
	var roots []string
	for name, body := range files {
		if path.Base(name) != "package.json" {
			continue
		}
		var pkg struct {
			Dependencies    map[string]json.RawMessage `json:"dependencies"`
			DevDependencies map[string]json.RawMessage `json:"devDependencies"`
		}
		if json.Unmarshal([]byte(body), &pkg) != nil {
			continue
		}
		has := func(dep string) bool { return pkg.Dependencies[dep] != nil || pkg.DevDependencies[dep] != nil }
		dir := path.Dir(name)
		packages[dir] = &sourcePackage{nest: has("@nestjs/core") || has("@nestjs/common"), next: has("next")}
		roots = append(roots, dir)
	}
	// Longest package root first, so a file belongs to its nearest package.
	sort.Slice(roots, func(i, j int) bool { return len(roots[i]) > len(roots[j]) })
	owner := func(name string) (string, *sourcePackage) {
		for _, dir := range roots {
			if dir == "." || name == dir || strings.HasPrefix(name, dir+"/") {
				return dir, packages[dir]
			}
		}
		return "", nil
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	// Package-wide settings: Nest global prefix and URI versioning, Next basePath.
	for _, name := range names {
		_, pkg := owner(name)
		if pkg == nil {
			continue
		}
		body := files[name]
		if pkg.nest {
			if m := nestGlobalPrefix.FindStringSubmatch(body); m != nil && pkg.globalPrefix == "" {
				pkg.globalPrefix = m[1]
			}
			if nestURIVersioning.MatchString(body) {
				pkg.uriVersioning = true
				if m := nestDefaultVersion.FindStringSubmatch(body); m != nil {
					pkg.defaultVersion = m[1]
				}
			}
		}
		if pkg.next && strings.HasPrefix(path.Base(name), "next.config.") {
			if m := nextBasePath.FindStringSubmatch(body); m != nil {
				pkg.nextBasePath = m[1]
			}
		}
	}
	dtos := map[string][]sourceRouteParam{}
	for _, name := range names {
		if _, pkg := owner(name); pkg != nil && pkg.nest {
			collectSourceDTOs(files[name], dtos)
		}
	}
	var routes []SourceRoute
	skipped := 0
	for _, name := range names {
		dir, pkg := owner(name)
		if pkg == nil {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(name, dir), "/")
		if pkg.nest && strings.Contains(files[name], "@Controller(") {
			found, unsupported := extractNestRoutes(name, files[name], pkg, dtos)
			routes = append(routes, found...)
			skipped += unsupported
		}
		if pkg.next {
			routes = append(routes, extractNextRoutes(name, rel, files[name], pkg)...)
		}
	}
	if skipped > 0 {
		gaps = append(gaps, countGap(skipped, "source route uses a wildcard, regular-expression or computed path and was not added", "source routes use wildcard, regular-expression or computed paths and were not added"))
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})
	return dedupeSourceRoutes(routes), gaps
}

func countGap(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}

func dedupeSourceRoutes(routes []SourceRoute) []SourceRoute {
	seen := map[string]bool{}
	out := routes[:0]
	for _, route := range routes {
		key := route.Method + " " + route.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, route)
	}
	return out
}

func readSourceRouteFiles(ctx context.Context, root string) (map[string]string, []string) {
	files := map[string]string{}
	var gaps []string
	handle, err := os.OpenRoot(root)
	if err != nil {
		return files, []string{"source directory for route extraction cannot be opened"}
	}
	defer handle.Close()
	entries, total, bounded, oversized := 0, 0, false, 0
	_ = fs.WalkDir(handle.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			return nil
		}
		entries++
		if entries > bundledSASTMaxEntries {
			bounded = true
			return fs.SkipAll
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if sourceRouteSkipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !sourceRouteFile(name) {
			return nil
		}
		if len(files) >= bundledSASTMaxFiles {
			bounded = true
			return fs.SkipAll
		}
		file, err := handle.Open(name)
		if err != nil {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(file, bundledSASTMaxFile+1))
		file.Close()
		if err != nil {
			return nil
		}
		if len(body) > bundledSASTMaxFile {
			oversized++
			return nil
		}
		if total+len(body) > bundledSASTMaxBytes {
			bounded = true
			return fs.SkipAll
		}
		total += len(body)
		files[name] = string(body)
		return nil
	})
	if bounded {
		gaps = append(gaps, "source route extraction reached its file or size limit; some routes may be missing")
	}
	if oversized > 0 {
		gaps = append(gaps, countGap(oversized, "source file over 1 MiB was not read for routes", "source files over 1 MiB were not read for routes"))
	}
	if ctx.Err() != nil {
		gaps = append(gaps, "source route extraction was cancelled")
	}
	return files, gaps
}

func sourceRouteFile(name string) bool {
	base := path.Base(name)
	if base == "package.json" || strings.HasPrefix(base, "next.config.") {
		return true
	}
	for _, suffix := range []string{".d.ts", ".spec.ts", ".test.ts", ".e2e-spec.ts", ".spec.js", ".test.js", ".spec.tsx", ".test.tsx"} {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	switch path.Ext(base) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts":
		return true
	}
	return false
}

var (
	nestGlobalPrefix   = regexp.MustCompile(`setGlobalPrefix\(\s*['"\x60]([^'"\x60]*)['"\x60]`)
	nestURIVersioning  = regexp.MustCompile(`enableVersioning\(\s*\{[^}]*VersioningType\.URI`)
	nestDefaultVersion = regexp.MustCompile(`defaultVersion\s*:\s*['"]([^'"]+)['"]`)
	nextBasePath       = regexp.MustCompile(`basePath\s*:\s*['"](/[^'"]*)['"]`)
	nestControllerDec  = regexp.MustCompile(`@Controller\(`)
	nestClassDecl      = regexp.MustCompile(`\bclass\s+([A-Za-z_$][\w$]*)`)
	nestVerbDec        = regexp.MustCompile(`@(Get|Post|Put|Patch|Delete|Head|Options|All)\(`)
	nestMethodName     = regexp.MustCompile(`^(?:\s|public\b|private\b|protected\b|static\b|async\b|readonly\b)*([A-Za-z_$][\w$]*)\s*(?:<[^>()]*>)?\s*\(`)
	nestVersionDec     = regexp.MustCompile(`@Version\(\s*['"]([^'"]+)['"]`)
	nestQueryNamed     = regexp.MustCompile(`@Query\(\s*['"]([\w.\-\[\]]+)['"][^)]*\)\s*(?:public\s+|private\s+|readonly\s+)*[\w$]+\??\s*:\s*([\w$]+)?`)
	nestQueryDTO       = regexp.MustCompile(`@Query\(\s*(?:new\s+[\w.]+\([^)]*\)\s*)?\)\s*(?:public\s+|private\s+|readonly\s+)*[\w$]+\??\s*:\s*([A-Z][\w$]*)`)
	stringLiteral      = regexp.MustCompile(`['"\x60]([^'"\x60]*)['"\x60]`)
	objectPathField    = regexp.MustCompile(`\bpath\s*:\s*(\[[^\]]*\]|['"\x60][^'"\x60]*['"\x60])`)
	objectVersionField = regexp.MustCompile(`\bversion\s*:\s*(\[[^\]]*\]|['"\x60][^'"\x60]*['"\x60])`)
	classBodyDecl      = regexp.MustCompile(`\bclass\s+([A-Za-z_$][\w$]*)[^{]*\{`)
	dtoProperty        = regexp.MustCompile(`(?m)^\s*(?:@[\w$.]+\([^)\n]*\)\s*)*(?:readonly\s+|public\s+)?([A-Za-z_$][\w$]*)(\?|!)?\s*:\s*([A-Za-z_$][\w$]*)(?:\[\])?\s*(?:[;=]|$)`)
	nestPathParam      = regexp.MustCompile(`:([A-Za-z_$][\w$]*)(\([^)]*\))?\??`)
)

// matchingClose returns the index of the bracket closing s[open], skipping
// string literals and comments, or -1.
func matchingClose(s string, open int) int {
	if open < 0 || open >= len(s) {
		return -1
	}
	openCh := s[open]
	closeCh := map[byte]byte{'(': ')', '{': '}', '[': ']'}[openCh]
	depth := 0
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"', '`':
			for j := i + 1; j < len(s); j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == c {
					i = j
					break
				}
			}
		case '/':
			if i+1 < len(s) && s[i+1] == '/' {
				if nl := strings.IndexByte(s[i:], '\n'); nl >= 0 {
					i += nl
				} else {
					return -1
				}
			} else if i+1 < len(s) && s[i+1] == '*' {
				if end := strings.Index(s[i+2:], "*/"); end >= 0 {
					i += end + 3
				} else {
					return -1
				}
			}
		case openCh:
			depth++
		case closeCh:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// literalPaths reads the path argument(s) of a Nest decorator: nothing, a
// string, an array of strings, or an options object with path/version.
func literalPaths(args string) (paths []string, versions []string, dynamic bool) {
	args = strings.TrimSpace(args)
	if args == "" {
		return []string{""}, nil, false
	}
	readList := func(raw string) []string {
		var out []string
		for _, m := range stringLiteral.FindAllStringSubmatch(raw, -1) {
			out = append(out, m[1])
		}
		return out
	}
	switch args[0] {
	case '\'', '"', '`':
		if strings.Contains(args, "${") {
			return nil, nil, true
		}
		if m := stringLiteral.FindStringSubmatch(args); m != nil {
			return []string{m[1]}, nil, false
		}
	case '[':
		if list := readList(args); len(list) > 0 {
			return list, nil, false
		}
	case '{':
		paths = []string{""}
		if m := objectPathField.FindStringSubmatch(args); m != nil {
			paths = readList(m[1])
		}
		if m := objectVersionField.FindStringSubmatch(args); m != nil {
			versions = readList(m[1])
		}
		return paths, versions, len(paths) == 0
	}
	return nil, nil, true
}

func lineAt(s string, offset int) int {
	return strings.Count(s[:offset], "\n") + 1
}

func extractNestRoutes(file, body string, pkg *sourcePackage, dtos map[string][]sourceRouteParam) ([]SourceRoute, int) {
	var routes []SourceRoute
	unsupported := 0
	for _, loc := range nestControllerDec.FindAllStringIndex(body, -1) {
		open := loc[1] - 1
		closeIdx := matchingClose(body, open)
		if closeIdx < 0 {
			continue
		}
		controllerPaths, controllerVersions, dynamic := literalPaths(body[open+1 : closeIdx])
		if dynamic {
			unsupported++
			continue
		}
		classLoc := nestClassDecl.FindStringSubmatchIndex(body[closeIdx:])
		if classLoc == nil {
			continue
		}
		className := body[closeIdx+classLoc[2] : closeIdx+classLoc[3]]
		braceRel := strings.IndexByte(body[closeIdx+classLoc[1]:], '{')
		if braceRel < 0 {
			continue
		}
		classOpen := closeIdx + classLoc[1] + braceRel
		classClose := matchingClose(body, classOpen)
		if classClose < 0 {
			continue
		}
		classBody := body[classOpen:classClose]
		for _, verb := range nestVerbDec.FindAllStringSubmatchIndex(classBody, -1) {
			method := strings.ToUpper(classBody[verb[2]:verb[3]])
			argOpen := verb[1] - 1
			argClose := matchingClose(classBody, argOpen)
			if argClose < 0 {
				continue
			}
			methodPaths, _, dynamicMethod := literalPaths(classBody[argOpen+1 : argClose])
			if dynamicMethod {
				unsupported++
				continue
			}
			// Decorators above the verb (back to the previous member) and below it
			// may carry @Version.
			methodVersion := ""
			before := classBody[:verb[0]]
			if cut := strings.LastIndexAny(before, "};"); cut >= 0 {
				before = before[cut+1:]
			}
			if m := nestVersionDec.FindStringSubmatch(before); m != nil {
				methodVersion = m[1]
			}
			// Skip any further decorators, collecting @Version.
			cursor := argClose + 1
			for {
				rest := strings.TrimLeft(classBody[cursor:], " \t\r\n")
				cursor = len(classBody) - len(rest)
				if !strings.HasPrefix(rest, "@") {
					break
				}
				paren := strings.IndexByte(rest, '(')
				if paren < 0 {
					break
				}
				end := matchingClose(classBody, cursor+paren)
				if end < 0 {
					break
				}
				if m := nestVersionDec.FindStringSubmatch(classBody[cursor : end+1]); m != nil {
					methodVersion = m[1]
				}
				cursor = end + 1
			}
			nameLoc := nestMethodName.FindStringSubmatchIndex(classBody[cursor:])
			if nameLoc == nil {
				continue
			}
			handler := classBody[cursor+nameLoc[2] : cursor+nameLoc[3]]
			paramsOpen := cursor + nameLoc[1] - 1
			paramsClose := matchingClose(classBody, paramsOpen)
			params := ""
			if paramsClose > paramsOpen {
				params = classBody[paramsOpen+1 : paramsClose]
			}
			var query []sourceRouteParam
			for _, m := range nestQueryNamed.FindAllStringSubmatch(params, -1) {
				query = append(query, sourceRouteParam{Name: m[1], Type: m[2]})
			}
			for _, m := range nestQueryDTO.FindAllStringSubmatch(params, -1) {
				query = append(query, dtos[m[1]]...)
			}
			if method == "ALL" {
				method = "GET"
			}
			versions := controllerVersions
			if methodVersion != "" {
				versions = []string{methodVersion}
			}
			if len(versions) == 0 && pkg.defaultVersion != "" {
				versions = []string{pkg.defaultVersion}
			}
			if !pkg.uriVersioning {
				versions = nil
			}
			if len(versions) == 0 {
				versions = []string{""}
			}
			line := lineAt(body, classOpen+cursor+nameLoc[2])
			for _, version := range versions {
				for _, cp := range controllerPaths {
					for _, mp := range methodPaths {
						versionSegment := ""
						if version != "" {
							versionSegment = "v" + strings.TrimPrefix(version, "v")
						}
						routePath, ok := nestRoutePath(pkg.globalPrefix, versionSegment, cp, mp)
						if !ok {
							unsupported++
							continue
						}
						routes = append(routes, SourceRoute{Framework: "nestjs", Method: method, Path: routePath, File: file, Line: line, Handler: className + "." + handler, Query: query})
					}
				}
			}
		}
	}
	return routes, unsupported
}

// nestRoutePath joins Nest path parts and converts ":id" to "{id}". It rejects
// wildcard and regular-expression paths, which cannot be seeded as a request.
func nestRoutePath(parts ...string) (string, bool) {
	var segments []string
	for _, part := range parts {
		for _, segment := range strings.Split(part, "/") {
			if segment = strings.TrimSpace(segment); segment != "" {
				segments = append(segments, segment)
			}
		}
	}
	for i, segment := range segments {
		if strings.ContainsAny(segment, "*+") || strings.Contains(segment, "(.") {
			return "", false
		}
		segments[i] = nestPathParam.ReplaceAllString(segment, "{$1}")
		if strings.ContainsAny(segments[i], "()?:") {
			return "", false
		}
	}
	return "/" + strings.Join(segments, "/"), true
}

// collectSourceDTOs records each class's scalar properties, for @Query() DTOs.
func collectSourceDTOs(body string, dtos map[string][]sourceRouteParam) {
	for _, loc := range classBodyDecl.FindAllStringSubmatchIndex(body, -1) {
		name := body[loc[2]:loc[3]]
		open := loc[1] - 1
		closeIdx := matchingClose(body, open)
		if closeIdx < 0 {
			continue
		}
		classBody := body[open+1 : closeIdx]
		if strings.Contains(classBody, "constructor(") {
			// DTOs are plain property bags; services and controllers are not.
			continue
		}
		var props []sourceRouteParam
		for _, m := range dtoProperty.FindAllStringSubmatch(classBody, -1) {
			props = append(props, sourceRouteParam{Name: m[1], Type: m[3]})
			if len(props) >= 32 {
				break
			}
		}
		if len(props) > 0 {
			if _, exists := dtos[name]; !exists {
				dtos[name] = props
			}
		}
	}
}

var (
	nextRouteExports  = regexp.MustCompile(`export\s+(?:async\s+)?(?:function|const|let|var)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)
	nextReexportNames = regexp.MustCompile(`export\s*\{([^}]*)\}`)
	nextHTTPMethods   = regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)
	nextDynamic       = regexp.MustCompile(`^\[\[?(?:\.\.\.)?([A-Za-z_$][\w$-]*)\]\]?$`)
)

// extractNextRoutes maps a Next.js app/ or pages/ file to its URL route(s).
func extractNextRoutes(file, rel, body string, pkg *sourcePackage) []SourceRoute {
	rel = strings.TrimPrefix(rel, "src/")
	ext := path.Ext(rel)
	switch ext {
	case ".tsx", ".ts", ".jsx", ".js", ".mjs":
	default:
		return nil
	}
	stem := strings.TrimSuffix(rel, ext)
	var segments []string
	var methods []string
	optionalCatchAll := false
	switch {
	case strings.HasPrefix(stem, "app/") && (path.Base(stem) == "page" || path.Base(stem) == "route"):
		for _, segment := range strings.Split(path.Dir(stem), "/")[1:] {
			switch {
			case segment == "" || segment == ".":
				continue
			case strings.HasPrefix(segment, "(.") || strings.HasPrefix(segment, "(..") || strings.HasPrefix(segment, "(..."):
				return nil // intercepting route, not a URL of its own
			case strings.HasPrefix(segment, "(") && strings.HasSuffix(segment, ")"):
				continue // route group
			case strings.HasPrefix(segment, "@"):
				continue // parallel route slot
			case strings.HasPrefix(segment, "_"):
				return nil // private folder
			}
			if strings.HasPrefix(segment, "[[...") {
				optionalCatchAll = true
			}
			segments = append(segments, segment)
		}
		if path.Base(stem) == "route" {
			for _, m := range nextRouteExports.FindAllStringSubmatch(body, -1) {
				methods = append(methods, m[1])
			}
			for _, block := range nextReexportNames.FindAllStringSubmatch(body, -1) {
				for _, m := range nextHTTPMethods.FindAllStringSubmatch(block[1], -1) {
					methods = append(methods, m[1])
				}
			}
		}
	case strings.HasPrefix(stem, "pages/"):
		parts := strings.Split(stem, "/")[1:]
		last := parts[len(parts)-1]
		if strings.HasPrefix(last, "_") || last == "middleware" {
			return nil
		}
		if last == "index" {
			parts = parts[:len(parts)-1]
		}
		for _, segment := range parts {
			if strings.HasPrefix(segment, "[[...") {
				optionalCatchAll = true
			}
			segments = append(segments, segment)
		}
	default:
		return nil
	}
	if len(methods) == 0 {
		methods = []string{"GET"}
	}
	for i, segment := range segments {
		if m := nextDynamic.FindStringSubmatch(segment); m != nil {
			segments[i] = "{" + m[1] + "}"
		}
	}
	build := func(segments []string) string {
		route := "/" + strings.Join(segments, "/")
		if pkg.nextBasePath != "" {
			route = strings.TrimSuffix(pkg.nextBasePath, "/") + strings.TrimSuffix(route, "/")
			if route == "" {
				route = "/"
			}
		}
		return route
	}
	paths := []string{build(segments)}
	if optionalCatchAll && len(segments) > 0 {
		paths = append(paths, build(segments[:len(segments)-1]))
	}
	var routes []SourceRoute
	for _, routePath := range paths {
		for _, method := range dedupeStrings(methods) {
			routes = append(routes, SourceRoute{Framework: "nextjs", Method: method, Path: routePath, File: file, Line: 1})
		}
	}
	return routes
}

var sourceRoutePathParam = regexp.MustCompile(`\{([^}/]+)\}`)

// SourceRoutesToAPIEndpoints converts routes into inventory operations for one
// URL target. Read-only routes without path parameters are dispatchable;
// {param} routes wait for runtime path values (value harvesting); other methods
// are inventory-only, like every unsafe method.
func SourceRoutesToAPIEndpoints(routes []SourceRoute, targetID, sourceTargetID string) []APIEndpoint {
	out := make([]APIEndpoint, 0, len(routes))
	for _, route := range routes {
		endpoint := APIEndpoint{Method: route.Method, Path: route.Path, TargetID: targetID, DefinitionID: "source-routes:" + sourceTargetID, OperationID: strings.TrimSpace(route.Handler + " " + route.File), Source: sourceRoutesTool}
		for _, m := range sourceRoutePathParam.FindAllStringSubmatch(route.Path, -1) {
			endpoint.Parameters = append(endpoint.Parameters, APIParameter{Name: m[1], Location: "path", Required: true})
			endpoint.MissingInputs = append(endpoint.MissingInputs, "path:"+m[1])
		}
		seenQuery := map[string]bool{}
		for _, q := range route.Query {
			if seenQuery[q.Name] {
				continue
			}
			seenQuery[q.Name] = true
			endpoint.Parameters = append(endpoint.Parameters, APIParameter{Name: q.Name, Location: "query", SchemaType: q.Type, Placeholder: sourceQueryPlaceholder(q.Type)})
		}
		readOnly := route.Method == "GET" || route.Method == "HEAD"
		switch {
		case len(endpoint.MissingInputs) > 0:
			endpoint.Reason = "path parameters have no supplied values"
		case !readOnly:
			endpoint.Resolved, endpoint.Reason = true, "unsafe or state-changing method is inventory-only"
		default:
			endpoint.Resolved, endpoint.Eligible = true, true
		}
		out = append(out, endpoint)
	}
	return out
}

// sourceQueryPlaceholder is a labelled stand-in value by declared type, so a
// query parameter exists for parameter-based checks. Never operator input.
func sourceQueryPlaceholder(kind string) string {
	switch strings.ToLower(kind) {
	case "number", "int", "integer", "bigint":
		return "1"
	case "boolean", "bool":
		return "true"
	case "date":
		return "2024-01-01"
	}
	return "test"
}

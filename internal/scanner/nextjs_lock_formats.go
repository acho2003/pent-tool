package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var nextjsLegacyPackageName = regexp.MustCompile(`^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$`)

const nextjsLockMaxDepth = 32
const nextjsLockYAMLMaxBytes = 1 << 20
const nextjsLockYAMLMaxNodes = 100000

func nextjsLockGap(result *nextjsDepsManifest, message string) {
	for _, old := range result.Gaps {
		if old == message {
			return
		}
	}
	result.Gaps = append(result.Gaps, message)
}
func nextjsLockAdd(result *nextjsDepsManifest, resolution nextjsLockedResolution) {
	if !exactNextjsLockVersion(resolution.Version) {
		nextjsLockGap(result, "a Next.js record lacks an exact supported version")
		return
	}
	if len(result.Resolutions) >= nextjsDepsMaxResolutions {
		nextjsLockGap(result, "Next.js resolutions exceeded the 128-entry limit")
		return
	}
	result.Resolutions = append(result.Resolutions, resolution)
}
func nextjsPointerPart(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func parseNextjsLegacyLock(ctx context.Context, body []byte) (nextjsDepsManifest, error) {
	result := nextjsDepsManifest{Schema: 1, Catalog: nextjsDepsVersion, Format: "npm", LockVersion: 1, Resolutions: []nextjsLockedResolution{}}
	var root struct {
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(body, &root) != nil || root.Dependencies == nil {
		return result, fmt.Errorf("legacy npm dependency tree is unavailable")
	}
	var walk func(map[string]json.RawMessage, int, string, string)
	walk = func(deps map[string]json.RawMessage, depth int, pointer, install string) {
		if depth > nextjsLockMaxDepth {
			nextjsLockGap(&result, "legacy npm dependency nesting exceeded its depth limit")
			return
		}
		keys := make([]string, 0, len(deps))
		for key := range deps {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			if ctx.Err() != nil {
				return
			}
			if result.Packages >= nextjsDepsMaxPackages {
				nextjsLockGap(&result, "package record count exceeded the 20000-entry limit")
				return
			}
			result.Packages++
			var entry struct {
				Version      string                     `json:"version"`
				Dev          bool                       `json:"dev"`
				Optional     bool                       `json:"optional"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(deps[name], &entry) != nil {
				nextjsLockGap(&result, "legacy npm package record could not be decoded")
				continue
			}
			if len(name) > 256 || !nextjsLegacyPackageName.MatchString(name) {
				nextjsLockGap(&result, "legacy npm dependency name is unsupported")
				continue
			}
			location := pointer + "/" + nextjsPointerPart(name)
			version := entry.Version
			isNext := name == "next"
			if strings.HasPrefix(version, "npm:") {
				isNext = strings.HasPrefix(version, "npm:next@")
				if isNext {
					version = strings.TrimPrefix(version, "npm:next@")
				}
			}
			if isNext {
				nextjsLockAdd(&result, nextjsLockedResolution{Path: "legacy record", Version: version, Dev: entry.Dev, Optional: entry.Optional, Location: "#" + location})
			}
			if len(entry.Dependencies) > 0 {
				walk(entry.Dependencies, depth+1, location+"/dependencies", install+"/node_modules/"+name)
			}
		}
	}
	walk(root.Dependencies, 0, "/dependencies", "")
	if ctx.Err() != nil {
		return result, fmt.Errorf("lockfile analysis was cancelled")
	}
	return result, nil
}

// Parse to a node tree without invoking constructors or expanding aliases.
func nextjsLockYAML(body []byte) (*yaml.Node, error) {
	if len(body) > nextjsLockYAMLMaxBytes {
		return nil, fmt.Errorf("YAML lockfile exceeds the 1 MiB parsing limit")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var root yaml.Node
	if decoder.Decode(&root) != nil || len(root.Content) != 1 {
		return nil, fmt.Errorf("YAML lockfile could not be decoded")
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("multiple YAML lockfile documents are unsupported")
	}
	count := 0
	var walk func(*yaml.Node, int) error
	walk = func(node *yaml.Node, depth int) error {
		count++
		if count > nextjsLockYAMLMaxNodes || depth > nextjsLockMaxDepth {
			return fmt.Errorf("YAML lockfile node or depth limit reached")
		}
		if node.Kind == yaml.AliasNode || node.Anchor != "" {
			return fmt.Errorf("YAML lockfile aliases and anchors are unsupported")
		}
		if node.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for index := 0; index+1 < len(node.Content); index += 2 {
				key := node.Content[index]
				if key.Kind != yaml.ScalarNode || seen[key.Value] {
					return fmt.Errorf("YAML lockfile has an invalid or duplicate key")
				}
				seen[key.Value] = true
			}
		}
		for _, child := range node.Content {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root.Content[0], 0); err != nil {
		return nil, err
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("YAML lockfile root must be a mapping")
	}
	return root.Content[0], nil
}
func nextjsYAMLField(node *yaml.Node, name string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return node.Content[i+1]
		}
	}
	return nil
}
func nextjsYAMLValue(node *yaml.Node, name string) string {
	field := nextjsYAMLField(node, name)
	if field == nil || field.Kind != yaml.ScalarNode {
		return ""
	}
	return field.Value
}

func parseNextjsYAMLLock(ctx context.Context, body []byte, pnpm bool) (nextjsDepsManifest, error) {
	result := nextjsDepsManifest{Schema: 1, Catalog: nextjsDepsVersion, Resolutions: []nextjsLockedResolution{}}
	root, err := nextjsLockYAML(body)
	if err != nil {
		return result, err
	}
	var records *yaml.Node
	if pnpm {
		result.Format = "pnpm"
		version := nextjsYAMLValue(root, "lockfileVersion")
		switch version {
		case "5.4", "6.0", "9.0":
		default:
			return result, fmt.Errorf("pnpm lockfile version is unsupported")
		}
		result.FormatVersion = version
		records = nextjsYAMLField(root, "packages")
	} else {
		result.Format = "yarn-berry"
		version := nextjsYAMLValue(nextjsYAMLField(root, "__metadata"), "version")
		switch version {
		case "4", "6", "8", "10":
		default:
			return result, fmt.Errorf("Yarn lockfile metadata version is unsupported")
		}
		result.FormatVersion = version
		records = root
	}
	if records == nil || records.Kind != yaml.MappingNode {
		return result, fmt.Errorf("lockfile package mapping is unavailable")
	}
	for i := 0; i+1 < len(records.Content); i += 2 {
		if ctx.Err() != nil {
			return result, fmt.Errorf("lockfile analysis was cancelled")
		}
		if result.Packages >= nextjsDepsMaxPackages {
			nextjsLockGap(&result, "package record count exceeded the 20000-entry limit")
			break
		}
		result.Packages++
		key, entry := records.Content[i], records.Content[i+1]
		if key.Value == "__metadata" {
			continue
		}
		version := ""
		isNext := false
		if pnpm {
			identity := strings.TrimPrefix(key.Value, "/")
			if strings.HasPrefix(identity, "next@") {
				isNext = true
				version = strings.TrimPrefix(identity, "next@")
				version, _, _ = strings.Cut(version, "(")
			}
			if strings.HasPrefix(identity, "next/") {
				isNext = true
				version = strings.TrimPrefix(identity, "next/")
				version, _, _ = strings.Cut(version, "_")
			}
		} else {
			resolution := nextjsYAMLValue(entry, "resolution")
			isNext = strings.HasPrefix(resolution, "next@npm:")
			if isNext {
				version = strings.TrimPrefix(resolution, "next@npm:")
				if version != nextjsYAMLValue(entry, "version") {
					nextjsLockGap(&result, "Yarn Next.js version and resolution conflict")
					continue
				}
			}
			selectors, _ := nextjsYarnSelectors(key.Value)
			referenced := strings.HasPrefix(resolution, "next@")
			for _, selector := range selectors {
				referenced = referenced || nextjsYarnSelector(selector)
			}
			if !isNext && referenced {
				nextjsLockGap(&result, "a Yarn Next.js selector has an unsupported resolution")
				continue
			}
		}
		if !isNext {
			continue
		}
		if entry.Kind != yaml.MappingNode {
			nextjsLockGap(&result, "Next.js lockfile package record is not a mapping")
			continue
		}
		nextjsLockAdd(&result, nextjsLockedResolution{Path: fmt.Sprintf("record at line %d", key.Line), Version: version, Location: fmt.Sprintf(":%d", key.Line)})
	}
	if pnpm {
		versions := map[string]bool{}
		for _, resolution := range result.Resolutions {
			versions[resolution.Version] = true
		}
		check := func(importer *yaml.Node) {
			for _, group := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
				deps := nextjsYAMLField(importer, group)
				if deps == nil || deps.Kind != yaml.MappingNode {
					continue
				}
				for index := 0; index+1 < len(deps.Content); index += 2 {
					name, entry := deps.Content[index].Value, deps.Content[index+1]
					specifier := nextjsYAMLValue(entry, "specifier")
					next := name == "next" || strings.HasPrefix(specifier, "npm:next@")
					if name == "next" && strings.HasPrefix(specifier, "npm:") && !strings.HasPrefix(specifier, "npm:next@") {
						next = false
					}
					if !next {
						continue
					}
					version := nextjsYAMLValue(entry, "version")
					if entry.Kind == yaml.ScalarNode {
						version = entry.Value
					}
					version = strings.TrimPrefix(version, "next@")
					version, _, _ = strings.Cut(version, "(")
					if !versions[version] {
						nextjsLockGap(&result, "a declared pnpm Next.js dependency has no verified package resolution")
					}
				}
			}
		}
		check(root)
		importers := nextjsYAMLField(root, "importers")
		if importers != nil && importers.Kind == yaml.MappingNode {
			for index := 1; index < len(importers.Content); index += 2 {
				check(importers.Content[index])
			}
		}
	}
	return result, nil
}

func nextjsYarnSelectors(header string) ([]string, error) {
	var result []string
	start := 0
	quoted, escaped := false, false
	for index, char := range header {
		if escaped {
			escaped = false
			continue
		}
		if quoted && char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			quoted = !quoted
			continue
		}
		if char == ',' && !quoted {
			result = append(result, strings.TrimSpace(header[start:index]))
			start = index + 1
		}
	}
	if quoted {
		return nil, fmt.Errorf("Yarn selector quoting is incomplete")
	}
	result = append(result, strings.TrimSpace(header[start:]))
	for index, selector := range result {
		if strings.HasPrefix(selector, "\"") {
			decoded, err := strconv.Unquote(selector)
			if err != nil {
				return nil, fmt.Errorf("Yarn selector could not be decoded")
			}
			result[index] = decoded
		}
	}
	return result, nil
}
func nextjsYarnSelector(selector string) bool {
	if len(selector) < 2 {
		return false
	}
	split := strings.Index(selector[1:], "@")
	if split < 0 {
		return false
	}
	split++
	name, reference := selector[:split], selector[split+1:]
	if name == "next" {
		if strings.HasPrefix(reference, "npm:") {
			rest := strings.TrimPrefix(reference, "npm:")
			return strings.HasPrefix(rest, "next@") || !strings.Contains(rest, "@")
		}
		return true
	}
	return strings.HasPrefix(reference, "npm:next@")
}
func parseNextjsClassicLock(ctx context.Context, body []byte) (nextjsDepsManifest, error) {
	result := nextjsDepsManifest{Schema: 1, Catalog: nextjsDepsVersion, Format: "yarn-classic", FormatVersion: "1", Resolutions: []nextjsLockedResolution{}}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	active, versionSeen, bad := false, false, false
	version := ""
	entryLine, line := 0, 0
	flush := func() {
		if !active {
			return
		}
		if !versionSeen || bad {
			nextjsLockGap(&result, "Yarn Next.js record has missing or ambiguous version data")
			return
		}
		nextjsLockAdd(&result, nextjsLockedResolution{Path: fmt.Sprintf("record at line %d", entryLine), Version: version, Location: fmt.Sprintf(":%d", entryLine)})
	}
	for scanner.Scan() {
		line++
		if ctx.Err() != nil {
			return result, fmt.Errorf("lockfile analysis was cancelled")
		}
		text := scanner.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if text[0] != ' ' && text[0] != '\t' {
			flush()
			active, versionSeen, bad = false, false, false
			if result.Packages >= nextjsDepsMaxPackages {
				nextjsLockGap(&result, "package record count exceeded the 20000-entry limit")
				return result, nil
			}
			result.Packages++
			if !strings.HasSuffix(text, ":") {
				nextjsLockGap(&result, "Yarn lockfile entry header is unsupported")
				continue
			}
			selectors, err := nextjsYarnSelectors(strings.TrimSuffix(text, ":"))
			if err != nil {
				nextjsLockGap(&result, err.Error())
				continue
			}
			for _, selector := range selectors {
				active = active || nextjsYarnSelector(selector)
			}
			entryLine = line
			continue
		}
		if active && strings.HasPrefix(text, "  version ") {
			if versionSeen {
				bad = true
			}
			versionSeen = true
			version = strings.TrimSpace(strings.TrimPrefix(text, "  version "))
			if strings.HasPrefix(version, "\"") {
				decoded, err := strconv.Unquote(version)
				if err != nil {
					bad = true
				} else {
					version = decoded
				}
			}
		}
	}
	flush()
	if scanner.Err() != nil {
		nextjsLockGap(&result, "Yarn lockfile line limit or read failure interrupted parsing")
	}
	return result, nil
}

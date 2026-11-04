package scanner

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNextjsDependenciesAdditionalLockFormatsAndPrivacy(t *testing.T) {
	for _, tc := range []struct {
		name, file, body string
		count            int
	}{
		{"npm-v1", "package-lock.json", `{"lockfileVersion":1,"dependencies":{"next":{"version":"14.1.0","resolved":"https://user:REGISTRY_SECRET@private.test/next.tgz","dependencies":{"next":{"version":"15.0.0"}}},"alias":{"version":"npm:next@14.1.0"}}}`, 3},
		{"pnpm9", "pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: ^14.0.0\n        version: 14.1.0(react@18.2.0)\npackages:\n  next@14.1.0:\n    resolution: {tarball: 'https://user:REGISTRY_SECRET@private.test/next.tgz'}\n", 1},
		{"pnpm6", "pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /next@14.1.0(react@18.2.0):\n    resolution: {integrity: REGISTRY_SECRET}\n", 1},
		{"pnpm5", "pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /next/14.1.0_react@18.2.0:\n    resolution: {integrity: REGISTRY_SECRET}\n", 1},
		{"yarn1", "yarn.lock", "# yarn lockfile v1\nnext@^14.0.0, \"next@~14.1.0\":\n  version \"14.1.0\"\n  resolved \"https://user:REGISTRY_SECRET@private.test/next.tgz\"\n\"@scope/alias@npm:next@^15\":\n  version \"15.0.0\"\neslint-config-next@14.1.0:\n  version \"14.1.0\"\n", 2},
		{"yarn-modern", "yarn.lock", "__metadata:\n  version: 10\n\"next@npm:^14\":\n  version: 14.1.0\n  resolution: \"next@npm:14.1.0\"\n  checksum: REGISTRY_SECRET\n\"alias@npm:next@^15\":\n  version: 15.0.0\n  resolution: \"next@npm:15.0.0\"\n\"eslint-config-next@npm:14\":\n  version: 14.1.0\n  resolution: \"eslint-config-next@npm:14.1.0\"\n", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := nextjsDependencyRequest(t, map[string][]byte{tc.file: []byte(tc.body)})
			run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
			if run.Status != "completed" || run.Outcome != "SUCCESS_WITH_FINDINGS" {
				t.Fatalf("lockfile failed: %+v", run)
			}
			raw, err := os.ReadFile(run.SourceManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest nextjsDepsManifest
			if json.Unmarshal(raw, &manifest) != nil || len(manifest.Resolutions) != tc.count {
				t.Fatalf("wrong resolutions: %s", raw)
			}
			findings, errs := ParseRuns([]Run{run})
			if len(errs) > 0 || len(findings) == 0 {
				t.Fatal("version findings were lost")
			}
			artifact, _ := os.ReadFile(run.ArtifactPath)
			for _, secret := range []string{"REGISTRY_SECRET", "private.test", "https://user:"} {
				if strings.Contains(string(raw)+string(artifact), secret) {
					t.Fatal("registry values retained")
				}
			}
			for _, finding := range findings {
				if finding.Target != tc.file || finding.Confidence != "lockfile_version_match" {
					t.Fatal("source lockfile provenance lost")
				}
			}
		})
	}
}

func TestNextjsDependenciesMultipleManagersAndUnsupportedRecordsStayPartial(t *testing.T) {
	npm := []byte(`{"lockfileVersion":3,"packages":{"node_modules/next":{"version":"14.1.0"}}}`)
	yarn := []byte("# yarn lockfile v1\nnext@^15:\n  version \"15.0.0\"\n")
	req := nextjsDependencyRequest(t, map[string][]byte{"package-lock.json": npm, "yarn.lock": yarn})
	run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
	found, _ := ParseRun(run)
	targets := map[string]bool{}
	for _, finding := range found {
		targets[finding.Target] = true
	}
	if run.Outcome != "PARTIAL" || len(targets) != 2 {
		t.Fatalf("ambiguous manager evidence lost: %+v", run)
	}
	for _, tc := range []struct{ file, body string }{
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: &loop\n  next@14.1.0: *loop\n"},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\n---\npackages: {}\n"},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: workspace:*\n        version: link:../workspace\npackages: {}\n"},
		{"yarn.lock", "__metadata:\n  version: 8\nnext@npm:^14:\n  version: 14.1.0\n  resolution: next@npm:15.0.0\n"},
		{"yarn.lock", "# yarn lockfile v1\nnext@^14:\n  resolved \"https://private.test/secret\"\n"},
	} {
		req := nextjsDependencyRequest(t, map[string][]byte{tc.file: []byte(tc.body)})
		run := (nextjsDepsRunner{}).Run(t.Context(), req, Config{}, nil)
		if run.Outcome != "PARTIAL" {
			t.Fatalf("unsupported or ambiguous input looks clean: %+v", run)
		}
	}
}

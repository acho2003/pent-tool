package web

import (
	"encoding/json"
	"log"
	"os"
	"strings"
)

// defaultContentManifestPath is where the image build records the scanner
// binaries and template sets actually present (runtime/write-content-manifest.py).
const defaultContentManifestPath = "/usr/local/share/xalgorix/content-manifest.json"

// contentManifestToolIDs maps content-lock tool names to scanner registry IDs
// where the two differ, so plan fingerprints are keyed by registry ID.
var contentManifestToolIDs = map[string]string{
	"osv-scanner": "osv",
	"testssl.sh":  "testssl",
	"scout":       "scoutsuite",
}

// contentManifestPath returns the build-time content manifest location,
// overridable with XALGORIX_CONTENT_MANIFEST.
func contentManifestPath() string {
	if p := strings.TrimSpace(os.Getenv("XALGORIX_CONTENT_MANIFEST")); p != "" {
		return p
	}
	return defaultContentManifestPath
}

// loadToolVersions reads tool and template versions from the build-time
// content manifest. It never executes a scanner binary: versions identify the
// image, so they change on an upgrade but never between preview and start.
// A missing or unreadable manifest (dev builds) yields an empty map.
func loadToolVersions(path string) map[string]string {
	versions := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return versions
	}
	var manifest struct {
		Lock struct {
			NucleiTemplatesRevision string `json:"nuclei_templates_revision"`
		} `json:"lock"`
		Tools map[string]struct {
			Pinned        string   `json:"pinned"`
			Available     bool     `json:"available"`
			VersionOutput []string `json:"version_output"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		log.Printf("[content-manifest] ignoring unreadable %s: %v", path, err)
		return versions
	}
	for name, tool := range manifest.Tools {
		id := name
		if mapped, ok := contentManifestToolIDs[name]; ok {
			id = mapped
		}
		version := strings.TrimSpace(strings.Join(tool.VersionOutput, "\n"))
		switch {
		case !tool.Available:
			version = "unavailable (pinned " + tool.Pinned + ")"
		case version == "":
			version = "pinned " + tool.Pinned
		}
		versions[id] = version
	}
	if rev := strings.TrimSpace(manifest.Lock.NucleiTemplatesRevision); rev != "" {
		versions["nuclei-templates"] = rev
	}
	return versions
}

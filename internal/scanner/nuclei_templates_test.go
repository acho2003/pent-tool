package scanner

import (
	"slices"
	"testing"
)

func TestNucleiUsesPinnedTemplateDirectoryWhenConfigured(t *testing.T) {
	spec := buildNuclei(Request{Target: "https://example.test", ScanDir: t.TempDir()}, Config{
		NucleiPath: "nuclei", NucleiTemplatesDir: "/opt/nuclei-templates", RateRPS: 2,
	})
	if !slices.Contains(spec.args, "-t") {
		t.Fatalf("template flag missing: %v", spec.args)
	}
	for i, arg := range spec.args {
		if arg == "-t" && (i+1 >= len(spec.args) || spec.args[i+1] != "/opt/nuclei-templates") {
			t.Fatalf("wrong template directory: %v", spec.args)
		}
	}
}

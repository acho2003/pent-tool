package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTemplateInventoryListsEnabledRatherThanExecutedChecks(t *testing.T) {
	script := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'http/a.yaml\\nhttp/b.yaml\\nhttp/a.yaml\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	path, err := saveNucleiTemplateInventory(t.Context(), Request{ScanDir: t.TempDir()}, Config{NucleiPath: script, NucleiTemplatesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var inventory TemplateInventory
	if json.Unmarshal(data, &inventory) != nil || len(inventory.Templates) != 2 || inventory.ExecutedChecks != nil {
		t.Fatal(string(data))
	}
}
func TestNativeNucleiTemplateListing(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_NUCLEI_NATIVE") == "" {
		t.Skip("offline native Nuclei template listing opt-in")
	}
	path, err := saveNucleiTemplateInventory(t.Context(), Request{ScanDir: t.TempDir()}, Config{NucleiPath: "nuclei", NucleiTemplatesDir: "/opt/nuclei-templates"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var inventory TemplateInventory
	json.Unmarshal(data, &inventory)
	if len(inventory.Templates) < 100 {
		t.Fatal("native template inventory unexpectedly small", len(inventory.Templates))
	}
	t.Logf("enabled HTTP templates: %d; executed checks NOT TRACKED", len(inventory.Templates))
}

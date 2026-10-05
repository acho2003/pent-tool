package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundArtifactRejectsOversizedMetadataWithoutDestroyingEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	original := `{"alerts":[],"metadata":"` + strings.Repeat("x", 200) + `"}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "zap", 40); !bounded || err == nil {
		t.Fatal("unbounded metadata accepted", bounded, err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatal("diagnostic artifact changed")
	}
}
func TestBoundArtifactRetainsPrefixAndExactLargeNumbers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	original := `{"vulnerabilities":{"a":[{"id":9007199254740993,"evidence":"first"},{"evidence":"second"}],"b":[{"evidence":"third"}]}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "wapiti", 100); !bounded || err != nil {
		t.Fatal(bounded, err)
	}
	data, _ := os.ReadFile(path)
	if len(data) > 100 || !json.Valid(data) || !strings.Contains(string(data), "9007199254740993") || strings.Contains(string(data), "third") {
		t.Fatalf("invalid retained prefix %s", data)
	}
}
func TestBoundJSONLDoesNotRetainCutOrMalformedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.jsonl")
	if err := os.WriteFile(path, []byte("{\"id\":1}\n{\"id\":2,\"evidence\":\"long\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if bounded, err := boundWebArtifact(path, "nuclei", 15); !bounded || err != nil {
		t.Fatal(bounded, err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "{\"id\":1}\n" {
		t.Fatalf("cut record retained %s", data)
	}
	if err := os.WriteFile(path, []byte("{invalid}\n"+strings.Repeat("x", 50)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := boundWebArtifact(path, "nuclei", 20); err == nil {
		t.Fatal("malformed retained record accepted")
	}
}
func TestBoundArtifactReportsReadFailure(t *testing.T) {
	// /dev/null is not a regular output artifact. A directory exercises the
	// read failure without relying on Unix permission behavior under root.
	if _, err := boundWebArtifact(t.TempDir(), "zap", 1); err == nil {
		t.Fatal("artifact read failure hidden")
	}
}

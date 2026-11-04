package scanner

import (
	"strings"
	"testing"
)

func TestNextjsSourceMappingsBoundsAndPositions(t *testing.T) {
	for _, tc := range []struct {
		mapping                string
		sources, names, budget int
		gap                    bool
	}{
		{"AAAA", 1, 0, 10, false}, {"AAAAA", 1, 1, 10, false}, {"A;AACA", 1, 0, 10, false},
		{"", 0, 0, 10, false}, {"AA", 1, 0, 10, true}, {"AAAAAA", 1, 1, 10, true},
		{"ACAA", 1, 0, 10, true}, {"AADA", 1, 0, 10, true}, {"AAAAD", 1, 1, 10, true},
		{"AAAAA", 1, 0, 10, true}, {"g", 1, 0, 10, true}, {"///////A", 1, 0, 10, true},
		{"AAAA,", 1, 0, 10, true}, {"!", 1, 0, 10, true}, {"AAAA", 1, 0, 0, true},
		{"AAAA,D", 1, 0, 10, true},
		{"BAAA", 1, 0, 10, true},
	} {
		t.Run(tc.mapping, func(t *testing.T) {
			budget := tc.budget
			positions, err := nextjsSourceMappings(tc.mapping, tc.sources, tc.names, &budget)
			if (err != nil) != tc.gap {
				t.Fatalf("positions=%v err=%v", positions, err)
			}
		})
	}
	budget := 10
	positions, err := nextjsSourceMappings("AACA", 1, 0, &budget)
	if err != nil || positions[0].Line != 1 || positions[0].Column != 0 {
		t.Fatalf("original position lost: %v %v", positions, err)
	}
}

func TestNextjsSourceMapMalformedMappingsPreserveEmbeddedEvidence(t *testing.T) {
	entries, err := nextjsSourceMapContents([]byte(`{"version":3,"sources":["private-name.ts"],"sourcesContent":["retained evidence"],"mappings":"ACAA"}`))
	if err == nil || len(entries) != 1 || entries[0].Content != "retained evidence" || strings.Contains(err.Error(), "private-name") {
		t.Fatalf("partial evidence lost or diagnostics leaked: %v %v", entries, err)
	}
	entries, err = nextjsSourceMapContents([]byte(`{"version":3,"sources":["private-name.ts"],"sourcesContent":["retained evidence"],"mappings":"AACA"}`))
	if err != nil || len(entries) != 1 || !strings.Contains(entries[0].Location, "2:1; section-local") {
		t.Fatalf("mapped position missing: %v %v", entries, err)
	}
}

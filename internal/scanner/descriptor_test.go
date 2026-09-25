// internal/scanner/descriptor_test.go
package scanner

import (
	"slices"
	"strings"
	"testing"
)

func TestExistingRunnerDescriptors(t *testing.T) {
	p := NewPipeline(Config{})
	want := map[string]struct {
		phase  Phase
		weight Weight
	}{
		"nuclei":   {PhaseWeb, WeightLight},
		"zap":      {PhaseWeb, WeightHeavy},
		"testssl":  {PhaseWeb, WeightLight},
		"openvas":  {PhaseServer, WeightHeavy},
		"trivy":    {PhaseSAST, WeightLight},
		"semgrep":  {PhaseSAST, WeightLight},
		"gitleaks": {PhaseSAST, WeightLight},
		"osv":      {PhaseSAST, WeightLight},
		"vuls":     {PhaseServer, WeightLight},
	}
	if len(p.Runners) != len(want) {
		t.Fatalf("runner count = %d, want %d", len(p.Runners), len(want))
	}
	for _, r := range p.Runners {
		d := r.Descriptor()
		exp, ok := want[d.Name]
		if !ok {
			t.Fatalf("unexpected runner %q", d.Name)
		}
		if d.Phase != exp.phase || d.Weight != exp.weight {
			t.Errorf("%s: phase/weight = %q/%q, want %q/%q", d.Name, d.Phase, d.Weight, exp.phase, exp.weight)
		}
	}
}

func TestCatalog(t *testing.T) {
	got := Catalog()
	var names []string
	for _, ti := range got {
		names = append(names, ti.Name)
		if strings.TrimSpace(ti.Summary) == "" {
			t.Errorf("%s has no summary", ti.Name)
		}
		if ti.Selectable != slices.Contains(OrderedNames, ti.Name) {
			t.Errorf("%s selectable=%v, want %v", ti.Name, ti.Selectable, !ti.Selectable)
		}
	}
	want := []string{"subfinder", "httpx", "nmap", "nuclei", "zap", "testssl", "openvas", "vuls", "trivy", "semgrep", "gitleaks", "osv"}
	if !slices.Equal(names, want) {
		t.Fatalf("catalog order = %v, want %v", names, want)
	}
	for _, name := range OrderedNames {
		if n := slices.Index(names, name); n < 0 {
			t.Errorf("selectable scanner %s missing from catalog", name)
		}
	}
	phases := map[string]Phase{"subfinder": PhaseRecon, "nmap": PhaseRecon, "nuclei": PhaseWeb, "testssl": PhaseWeb, "openvas": PhaseServer, "vuls": PhaseServer, "semgrep": PhaseSAST, "osv": PhaseSAST}
	for _, ti := range got {
		if want, ok := phases[ti.Name]; ok && ti.Phase != want {
			t.Errorf("%s phase = %s, want %s", ti.Name, ti.Phase, want)
		}
	}
}

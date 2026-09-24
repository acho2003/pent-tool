// internal/scanner/descriptor_test.go
package scanner

import "testing"

func TestExistingRunnerDescriptors(t *testing.T) {
	p := NewPipeline(Config{})
	want := map[string]struct {
		phase  Phase
		weight Weight
	}{
		"nuclei":  {PhaseWeb, WeightLight},
		"zap":     {PhaseWeb, WeightHeavy},
		"openvas": {PhaseServer, WeightHeavy},
		"trivy":   {PhaseSAST, WeightLight},
		"vuls":    {PhaseServer, WeightLight},
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

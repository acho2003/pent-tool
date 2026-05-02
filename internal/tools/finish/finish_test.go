package finish

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestFinishToolReturnsSummaryAndMetadata(t *testing.T) {
	reg := tools.NewRegistry()
	Register(reg)

	res, err := reg.Execute("finish", map[string]string{"summary": "scan complete"})
	if err != nil {
		t.Fatalf("finish execute: %v", err)
	}
	if res.Output != "scan complete" {
		t.Fatalf("finish output = %q", res.Output)
	}
	if got, ok := res.Metadata["finished"].(bool); !ok || !got {
		t.Fatalf("finish metadata = %#v", res.Metadata)
	}
}

func TestFinishToolRequiresSummary(t *testing.T) {
	reg := tools.NewRegistry()
	Register(reg)

	if _, err := reg.Execute("finish", map[string]string{}); err == nil {
		t.Fatal("missing summary was accepted")
	}
}

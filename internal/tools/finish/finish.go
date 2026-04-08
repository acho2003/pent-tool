// Package finish provides the finish tool to end agent execution.
package finish

import (
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Register adds the finish tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "finish",
		Description: "Signal that the agent has completed its task. Provide a summary of findings.",
		Parameters: []tools.Parameter{
			{Name: "summary", Description: "Summary of what was done and key findings", Required: true},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return tools.Result{
				Output:   args["summary"],
				Metadata: map[string]any{"finished": true},
			}, nil
		},
	})
}

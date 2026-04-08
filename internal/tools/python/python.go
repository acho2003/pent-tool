// Package python provides the python_action tool via subprocess.
package python

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v3/internal/config"
	"github.com/xalgord/xalgorix/v3/internal/tools"
	"github.com/xalgord/xalgorix/v3/internal/tools/terminal"
)

// Register adds the python_action tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "python_action",
		Description: "Execute Python code in a subprocess. Python 3 must be installed.",
		Parameters: []tools.Parameter{
			{Name: "code", Description: "Python code to execute", Required: true},
			{Name: "timeout", Description: "Timeout in seconds (default: 1800 = 30 min)", Required: false},
		},
		Execute: executePython,
	})
}

func executePython(args map[string]string) (tools.Result, error) {
	code := args["code"]
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	timeoutSec := 1800 // 30 minutes — exploit scripts can run long
	if t := args["timeout"]; t != "" {
		if n, err := fmt.Sscanf(t, "%d", &timeoutSec); n != 1 || err != nil {
			return tools.Result{Error: fmt.Sprintf("invalid timeout value '%s': must be a number in seconds", t)}, nil
		}
		if timeoutSec <= 0 {
			timeoutSec = 1800
		}
		if timeoutSec > 7200 { // Cap at 2 hours
			timeoutSec = 7200
		}
	}

	// Find python3
	pythonBin := "python3"
	if _, err := exec.LookPath(pythonBin); err != nil {
		pythonBin = "python"
		if _, err := exec.LookPath(pythonBin); err != nil {
			return tools.Result{}, fmt.Errorf("Python not found. Install python3")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-c", code)
	cmd.Dir = config.Get().Workspace
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to start python process: %v", err)}, nil
	}

	// Register with terminal so watchdog knows we are active
	cleanCode := code
	if len(cleanCode) > 100 {
		cleanCode = cleanCode[:100] + "..."
	}
	terminal.TrackProcess(cmd, cancel, "python: "+strings.ReplaceAll(cleanCode, "\n", " "))
	defer terminal.UntrackProcess(cmd)

	err := cmd.Wait()

	var b strings.Builder
	if stdout.Len() > 0 {
		out := stdout.String()
		if len(out) > 15000 {
			out = out[:15000] + "\n... [OUTPUT TRUNCATED]"
		}
		b.WriteString(out)
	}

	if stderr.Len() > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		errOut := stderr.String()
		if len(errOut) > 5000 {
			errOut = errOut[:5000] + "\n... [TRUNCATED]"
		}
		b.WriteString(errOut)
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			b.WriteString(fmt.Sprintf("\n[TIMEOUT: exceeded %ds]", timeoutSec))
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitErr.ExitCode()))
		}
	}

	if b.Len() == 0 {
		b.WriteString("(no output)")
	}

	return tools.Result{Output: b.String()}, nil
}

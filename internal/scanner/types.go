// Package scanner implements Xalgorix's deterministic security-scanner
// pipeline. It deliberately has no dependency on internal/agent or internal/llm.
package scanner

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

const SchemaVersion = 2

var OrderedNames = []string{"nuclei", "zap", "openvas", "trivy", "vuls"}

// NormalizeScanners validates an operator's scanner selection and returns it in
// pipeline order, deduplicated. An empty selection means the whole pipeline, so
// it normalizes to nil rather than to every name: a scan saved today keeps
// running whatever the pipeline contains tomorrow.
func NormalizeScanners(names []string) ([]string, error) {
	selected := map[string]bool{}
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !slices.Contains(OrderedNames, name) {
			return nil, fmt.Errorf("unknown scanner %q (known: %s)", raw, strings.Join(OrderedNames, ", "))
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(selected))
	for _, name := range OrderedNames {
		if selected[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

type Artifact struct {
	Kind string `json:"kind,omitempty"`
	Ref  string `json:"ref,omitempty"`
}

type Request struct {
	Target string `json:"target"`
	// Scanners restricts this request to the named scanners. Empty runs the
	// whole pipeline; every name must be one of OrderedNames.
	Scanners    []string `json:"-"`
	ScanDir     string   `json:"-"`
	Artifact    Artifact `json:"artifact,omitempty"`
	VulsSSHHost string   `json:"vuls_ssh_host,omitempty"`
	TargetAuth  string   `json:"-"`
}

type Run struct {
	Scanner      string `json:"scanner"`
	Scope        string `json:"scope,omitempty"`
	Target       string `json:"target"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at,omitempty"`
	FinishedAt   string `json:"finished_at,omitempty"`
	ExitCode     int    `json:"exit_code,omitempty"`
	Reason       string `json:"reason,omitempty"`
	StdoutPath   string `json:"stdout_path,omitempty"`
	StderrPath   string `json:"stderr_path,omitempty"`
	ArtifactPath string `json:"artifact_path,omitempty"`
	Checksum     string `json:"checksum,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
}

func (r Run) Terminal() bool {
	switch r.Status {
	case "completed", "failed", "cancelled", "not_applicable", "skipped":
		return true
	default:
		return false
	}
}

type Event struct {
	Type     string
	Scanner  string
	Stream   string
	Sequence int64
	Output   string
	Run      Run
}

type Config struct {
	NucleiPath        string
	TrivyPath         string
	VulsPath          string
	VulsSSHConfigPath string

	ZAPURL    string
	ZAPAPIKey string
	GVMHost   string
	GVMPort   int
	GVMSocket string
	GVMUser   string
	GVMPass   string

	RateRPS        int
	ScanHeaders    []string
	MaxOutputBytes int64
	NucleiTimeout  time.Duration
	ZAPTimeout     time.Duration
	OpenVASTimeout time.Duration
	TrivyTimeout   time.Duration
	VulsTimeout    time.Duration
}

type EmitFunc func(Event)

type Runner interface {
	Name() string
	Descriptor() Descriptor
	Run(context.Context, Request, Config, EmitFunc) Run
}

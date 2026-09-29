package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// kubeBenchRunner runs the CIS Kubernetes benchmark (kube-bench) — a read-only
// configuration audit. It is an assessment-only, opt-in runner for KUBERNETES /
// COMPLIANCE assessments. kube-bench inspects the cluster/node it can reach; the
// operator is responsible for running Xalgorix where kube-bench has that access
// (on a node, or deployed in-cluster). It sends no traffic to workloads.
type kubeBenchRunner struct{}

func (kubeBenchRunner) Name() string { return "kube-bench" }
func (kubeBenchRunner) Descriptor() Descriptor {
	return Descriptor{Name: "kube-bench", Summary: "CIS Kubernetes benchmark checks", Phase: PhaseKubernetes, Weight: WeightLight, Applies: appliesToHost}
}
func (r kubeBenchRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return executeSpec(ctx, r.Name(), req, cfg, buildKubeBench(req, cfg), emit)
}

func buildKubeBench(req Request, cfg Config) commandSpec {
	if strings.TrimSpace(cfg.KubeBenchPath) == "" {
		return commandSpec{notApp: "kube-bench executable is not configured", timeout: cfg.KubeBenchTimeout}
	}
	base := filepath.Join(req.ScanDir, "scanner-output", "kube-bench")
	artifact := filepath.Join(base, "results.json")
	// Read-only benchmark: `run` executes the CIS checks; --json emits a machine
	// readable report; --outputfile keeps it under the scan dir. No flags here
	// change cluster state.
	args := []string{"run", "--json", "--outputfile", artifact, "--noremediations=false"}
	return commandSpec{
		path:     cfg.KubeBenchPath,
		args:     args,
		artifact: artifact,
		timeout:  cfg.KubeBenchTimeout,
		// kube-bench exits non-zero when checks FAIL/WARN; that is a completed
		// audit with findings, not a run error.
		okExit: map[int]bool{1: true, 2: true, 3: true},
		prepare: func() error {
			return os.MkdirAll(base, 0o700)
		},
	}
}

// kube-bench --json shape (subset): a top-level object with a Controls array,
// each control has Tests, each test has Results (the individual checks).
type kubeBenchReport struct {
	Controls []kubeBenchControl `json:"Controls"`
}
type kubeBenchControl struct {
	ID    string          `json:"id"`
	Text  string          `json:"text"`
	Tests []kubeBenchTest `json:"tests"`
}
type kubeBenchTest struct {
	Section string            `json:"section"`
	Desc    string            `json:"desc"`
	Results []kubeBenchResult `json:"results"`
}
type kubeBenchResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Status      string `json:"status"` // PASS | FAIL | WARN | INFO
	Remediation string `json:"remediation"`
	Scored      bool   `json:"scored"`
}

// parseKubeBench turns FAIL/WARN checks into findings. PASS/INFO are not
// findings. kube-bench can emit either a single JSON object or one object per
// benchmark target (newline-delimited); both are handled.
func parseKubeBench(artifact string) ([]Finding, error) {
	data, err := os.ReadFile(artifact)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil, nil
	}

	var reports []kubeBenchReport
	// Try a single object first; fall back to newline-delimited objects.
	var single kubeBenchReport
	if json.Unmarshal([]byte(text), &single) == nil && len(single.Controls) > 0 {
		reports = append(reports, single)
	} else {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rep kubeBenchReport
			if json.Unmarshal([]byte(line), &rep) == nil {
				reports = append(reports, rep)
			}
		}
	}

	var findings []Finding
	i := 0
	for _, rep := range reports {
		for _, ctrl := range rep.Controls {
			for _, test := range ctrl.Tests {
				for _, res := range test.Results {
					sev := kubeBenchSeverity(res.Status, res.Scored)
					if sev == "" {
						continue // PASS / INFO -> not a finding
					}
					title := strings.TrimSpace(res.TestDesc)
					if title == "" {
						title = "CIS Kubernetes benchmark " + res.TestNumber
					}
					findings = append(findings, Finding{
						SourceID:    fmt.Sprintf("kube-bench:%s", firstNonEmptyKB(res.TestNumber, fmt.Sprintf("%d", i))),
						Scanner:     "kube-bench",
						Title:       title,
						Severity:    sev,
						Endpoint:    strings.TrimSpace(res.TestNumber),
						Description: strings.TrimSpace(ctrl.Text + " / " + test.Desc),
						Remediation: strings.TrimSpace(res.Remediation),
						CWE:         "CWE-1008", // ASCSM — weak configuration / hardening
					})
					i++
				}
			}
		}
	}
	return findings, nil
}

// kubeBenchSeverity maps a check status to our scale. FAIL on a scored control
// is the strongest signal; WARN is advisory. PASS/INFO produce no finding.
func kubeBenchSeverity(status string, scored bool) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "FAIL":
		if scored {
			return "medium"
		}
		return "low"
	case "WARN":
		return "low"
	default:
		return ""
	}
}

func firstNonEmptyKB(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestLynisRequiresBoundAliasAndUsesFixedRemoteCommand(t *testing.T) {
	for _, alias := range []string{"", "host;touch /tmp/pwned", "-oProxyCommand=evil"} {
		spec := buildLynis(Request{TypedAssessment: true, VulsSSHHost: alias}, Config{})
		if spec.notApp == "" {
			t.Fatalf("unsafe alias %q was accepted", alias)
		}
	}
	sshConfig := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(sshConfig, []byte("Host audit-host\n  HostName 192.0.2.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := buildLynis(Request{TypedAssessment: true, VulsSSHHost: "audit-host", ScanDir: t.TempDir()}, Config{SSHPath: "ssh", VulsSSHConfigPath: sshConfig})
	if spec.notApp != "" || spec.args[len(spec.args)-2] != "audit-host" || spec.args[len(spec.args)-1] != "lynis audit system --quick --nocolors" || !strings.Contains(strings.Join(spec.args, " "), "StrictHostKeyChecking=yes") {
		t.Fatalf("Lynis command was not bounded: %+v", spec)
	}
}

func TestLynisParsesOnlySummaryControlsAndRunsThroughTypedHostJob(t *testing.T) {
	root := t.TempDir()
	ssh := filepath.Join(root, "fake-ssh")
	script := "#!/bin/sh\nprintf '%s\\n' 'Warnings (1):' '  - Outdated packages detected [PKGS-7392]' 'Suggestions (1):' '  - Review SSH settings [SSH-7408]' 'Hardening index: 70'\n"
	if err := os.WriteFile(ssh, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	runner := lynisRunner{}
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "host", Kind: assessment.KindHost, Value: "host.example.test"}}}, Fingerprint: "sha256:lynis", Jobs: []PlanJob{{ID: "lynis:host", Scanner: "lynis", TargetID: "host", Target: "host.example.test", Variant: "lynis", State: PlanConditional}}}
	pipeline := &Pipeline{Config: Config{SSHPath: ssh, AssessmentSSHAliases: map[string]string{"host": "audit-host"}}, Runners: []Runner{runner}}
	runs := pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if len(runs) != 1 || runs[0].Status != "completed" {
		t.Fatalf("typed Lynis run failed: %+v", runs)
	}
	findings, err := ParseRun(runs[0])
	if err != nil || len(findings) != 2 || findings[0].SourceID != "lynis:warning:PKGS-7392" || findings[1].SourceID != "lynis:suggestion:SSH-7408" || findings[0].Severity != "medium" || findings[1].Severity != "low" {
		t.Fatalf("Lynis summary findings=%+v err=%v", findings, err)
	}
}

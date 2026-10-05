package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type correctnessProbe struct {
	name    string
	request Request
}

func (p *correctnessProbe) Name() string           { return p.name }
func (p *correctnessProbe) Descriptor() Descriptor { return Descriptor{Name: p.name, Phase: PhaseWeb} }
func (p *correctnessProbe) Run(_ context.Context, r Request, _ Config, _ EmitFunc) Run {
	p.request = r
	return Run{Scanner: p.name, Status: "completed"}
}

func TestAssessmentForwardsWapitiAndDalfoxPolicyAndAuth(t *testing.T) {
	for _, name := range []string{"wapiti", "dalfox"} {
		t.Run(name, func(t *testing.T) {
			p := &correctnessProbe{name: name}
			bin := filepath.Join(t.TempDir(), name)
			marker := bin + ".args"
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + marker + "\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-o\" ]; then shift; printf '{\"vulnerabilities\":{}}' > \"$1\"; fi; shift; done\n"
			if name == "dalfox" {
				script = strings.ReplaceAll(script, `{\"vulnerabilities\":{}}`, `[]`)
				script = strings.ReplaceAll(script, `{"vulnerabilities":{}}`, `[]`)
			}
			if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			cfg := assessment.AssessmentConfig{TestEnvironment: true, Targets: []assessment.Target{{ID: "app", Kind: assessment.KindURL, Value: "https://app.test/?q=1"}}, Access: []assessment.AccessBinding{{Kind: assessment.AccessApplicationHeaders, TargetIDs: []string{"app"}}}}
			pipeline := Pipeline{Runners: []Runner{p}, Config: Config{KatanaPath: "/unavailable", WapitiPath: bin, DalfoxPath: bin, AssessmentAuthHeaders: map[string][]string{"app": {"Cookie: session=verified"}}, AssessmentAuthRefresh: map[string]func(context.Context, []string) ([]string, error){"app": func(_ context.Context, h []string) ([]string, error) { return h, nil }}}}
			runs := pipeline.RunAssessmentJobs(t.Context(), AssessmentPlan{Config: cfg, Fingerprint: "test", Jobs: []PlanJob{{Scanner: name, TargetID: "app", Target: cfg.Targets[0].Value, State: PlanSelected}}}, t.TempDir(), nil, nil)
			args, _ := os.ReadFile(marker)
			if len(runs) != 1 || runs[0].Status != "completed" || !strings.Contains(string(args), "Cookie: session=verified") || !runs[0].Authenticated {
				t.Fatalf("policy/auth not forwarded: %+v %+v", p.request, runs)
			}
		})
	}
}

func TestWebResultValidation(t *testing.T) {
	for _, tc := range []struct{ name, content, outcome string }{{"zap", "{}", "PARSER_FAILED"}, {"zap", `{"alerts":[]}`, "SUCCESS_NO_FINDINGS"}, {"wapiti", "", "PARSER_FAILED"}, {"wapiti", `{"vulnerabilities":{}}`, "SUCCESS_NO_FINDINGS"}, {"nuclei", "", "SUCCESS_NO_FINDINGS"}} {
		t.Run(tc.name+tc.outcome, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "results")
			if err := os.WriteFile(p, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			r := Run{Scanner: tc.name, Status: "completed", ArtifactPath: p}
			validateWebResult(&r)
			if r.Outcome != tc.outcome {
				t.Fatalf("got %+v", r)
			}
		})
	}
	r := Run{Scanner: "zap", Status: "completed", ArtifactPath: filepath.Join(t.TempDir(), "missing")}
	validateWebResult(&r)
	if r.Outcome != "PARSER_FAILED" {
		t.Fatal(r)
	}
}

func TestZAPFlatEvidenceFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zap.json")
	os.WriteFile(p, []byte(`{"alerts":[{"pluginId":"1","url":"https://app.test/?q=1","method":"POST","param":"q","messageId":"42","attack":"sample","evidence":"observed"}]}`), 0600)
	fs, err := parseZAP(p)
	if err != nil || len(fs) != 1 || fs[0].Method != "POST" || fs[0].Parameter != "q" || fs[0].NativeMessageID != "42" || fs[0].Attack != "sample" {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestCredentialBindingDoesNotAuthorizeAlias(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", Port: 443, PathPrefix: "/"}, {Scheme: "https", Host: "alias.test", Port: 443, PathPrefix: "/"}})
	req := Request{Target: "https://app.test/", TargetAuth: "Cookie: secret", AppScope: &scope, EndpointTargets: []string{"https://app.test/a", "https://alias.test/a"}}
	constrainCredentialTargets(&req, nil, "wapiti")
	if len(req.EndpointTargets) != 1 || req.EndpointTargets[0] != "https://app.test/a" {
		t.Fatal(req.EndpointTargets)
	}
}

func TestInvalidNativeRecordsCannotBeCleanResults(t *testing.T) {
	for _, tc := range []struct{ scanner, content string }{{"zap", `{"alerts":null}`}, {"wapiti", `{"vulnerabilities":null}`}, {"nuclei", `{}`}} {
		path := filepath.Join(t.TempDir(), "results")
		os.WriteFile(path, []byte(tc.content), 0600)
		run := Run{Scanner: tc.scanner, Status: "completed", ArtifactPath: path}
		validateWebResult(&run)
		if run.Outcome != "PARSER_FAILED" || run.ExecutionOutcome != "SUCCESS" {
			t.Fatal(run)
		}
	}
}

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestImageReferencesAcceptTagsAndDigestsInWhiteBox(t *testing.T) {
	for _, ref := range []string{
		"hub.example.test/bcrs/bcrs-auth:6",
		"hub.example.test:5000/bcrs/bcrs_common_service:12",
		"nginx",
		"library/nginx:1.27",
		"hub.example.test/app@sha256:" + strings.Repeat("b", 64),
		"hub.example.test/app:6@sha256:" + strings.Repeat("c", 64),
	} {
		if reason := prepareLocalAssessmentResource(assessment.ModeWhiteBox, assessment.KindDockerImage, ref, "trivy"); reason != "" {
			t.Errorf("%s rejected: %s", ref, reason)
		}
	}
	for _, ref := range []string{"", "-image", "hub.example.test//app", "hub.example.test:port/app", "app:tag with space"} {
		if prepareLocalAssessmentResource(assessment.ModeWhiteBox, assessment.KindDockerImage, ref, "trivy") == "" {
			t.Errorf("%q accepted", ref)
		}
	}
}

func TestImageRegistryHost(t *testing.T) {
	cases := map[string]string{
		"hub.example.test/bcrs/auth:6": "hub.example.test",
		"HUB.example.test:5000/a:1":    "hub.example.test:5000",
		"localhost/app":                "localhost",
		"nginx:1.27":                   "docker.io",
		"library/nginx":                "docker.io",
	}
	for ref, want := range cases {
		if got := imageRegistryHost(ref); got != want {
			t.Errorf("%s: got %s want %s", ref, got, want)
		}
	}
	if normalizeRegistryHost("https://index.docker.io/") != "docker.io" || normalizeRegistryHost(" Hub.Example.Test/v2 ") != "hub.example.test" {
		t.Fatal("registry host not normalized")
	}
}

func TestTrivyRegistryCredentialOnlyForMatchingRegistry(t *testing.T) {
	ref := "hub.example.test/bcrs/bcrs-auth:6"
	cred := RegistryCredential{Registry: "https://hub.example.test", Username: "ci-reader", Password: "registry-secret"}
	spec := buildTrivy(Request{TypedAssessment: true, Artifact: Artifact{Kind: "image", Ref: ref}, ScanDir: t.TempDir(), RegistryCredential: cred}, Config{TrivyPath: "trivy"})
	if !slices.Contains(spec.env, "TRIVY_USERNAME=ci-reader") || !slices.Contains(spec.env, "TRIVY_PASSWORD=registry-secret") {
		t.Fatalf("registry login not passed through env: %v", spec.env)
	}
	if strings.Contains(strings.Join(spec.args, " "), "registry-secret") || strings.Contains(strings.Join(spec.args, " "), "ci-reader") {
		t.Fatal("registry credential placed on the command line")
	}
	if len(spec.args) < 2 || spec.args[len(spec.args)-2] != "--" || spec.args[len(spec.args)-1] != ref {
		t.Fatalf("image reference not passed after --: %v", spec.args)
	}
	other := buildTrivy(Request{TypedAssessment: true, Artifact: Artifact{Kind: "image", Ref: "docker.io/library/nginx:1"}, ScanDir: t.TempDir(), RegistryCredential: cred}, Config{TrivyPath: "trivy"})
	if len(other.env) != 0 {
		t.Fatal("registry credential sent to a different registry")
	}
	if len(other.limitations) != 1 || other.limitations[0].Kind != "registry_credential_not_applied" {
		t.Fatalf("mismatch not recorded: %+v", other.limitations)
	}
	none := buildTrivy(Request{TypedAssessment: true, Artifact: Artifact{Kind: "image", Ref: ref}, ScanDir: t.TempDir()}, Config{TrivyPath: "trivy"})
	if len(none.env) != 0 || len(none.limitations) != 0 {
		t.Fatal("anonymous image scan got credentials or limitations")
	}
}

func TestTrivyTagScanRecordsScannedDigest(t *testing.T) {
	dir := t.TempDir()
	spec := buildTrivy(Request{TypedAssessment: true, Artifact: Artifact{Kind: "image", Ref: "hub.example.test/bcrs/auth:6"}, ScanDir: dir}, Config{TrivyPath: "trivy"})
	if spec.completed == nil {
		t.Fatal("tag scan has no digest hook")
	}
	if err := os.MkdirAll(filepath.Dir(spec.artifact), 0o700); err != nil {
		t.Fatal(err)
	}
	digest := "hub.example.test/bcrs/auth@sha256:" + strings.Repeat("d", 64)
	if err := os.WriteFile(spec.artifact, []byte(`{"ArtifactName":"hub.example.test/bcrs/auth:6","Metadata":{"ImageID":"sha256:`+strings.Repeat("e", 64)+`","RepoDigests":["`+digest+`"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := Run{Status: "completed"}
	spec.completed(&run)
	if len(run.Limitations) != 1 || run.Limitations[0].Kind != LimitationMutableImageTag || !strings.Contains(run.Limitations[0].Reason, digest) {
		t.Fatalf("scanned digest not recorded: %+v", run.Limitations)
	}
	pinned := buildTrivy(Request{TypedAssessment: true, Artifact: Artifact{Kind: "image", Ref: "hub.example.test/app@sha256:" + strings.Repeat("a", 64)}, ScanDir: dir}, Config{TrivyPath: "trivy"})
	if pinned.completed != nil {
		t.Fatal("digest-pinned scan marked as mutable")
	}
}

func TestRegistryCredentialReachesTrivyJobAndIsRedacted(t *testing.T) {
	runner := &recordingTrivyRunner{}
	pipeline := &Pipeline{Runners: []Runner{runner}, Config: Config{AssessmentRegistryCreds: map[string]RegistryCredential{"img": {Registry: "hub.example.test", Username: "ci", Password: "registry-secret"}}}}
	ref := "hub.example.test/bcrs/auth:6"
	plan := AssessmentPlan{Config: assessment.AssessmentConfig{Mode: assessment.ModeWhiteBox, Targets: []assessment.Target{{ID: "img", Kind: assessment.KindDockerImage, Value: ref}}}, Fingerprint: "sha256:image", Jobs: []PlanJob{{ID: "trivy:img", Scanner: "trivy", TargetID: "img", Target: ref, Variant: "trivy", State: PlanConditional}}}
	pipeline.RunAssessmentJobs(t.Context(), plan, t.TempDir(), nil, nil)
	if len(runner.requests) != 1 {
		t.Fatalf("trivy job did not run: %d", len(runner.requests))
	}
	req := runner.requests[0]
	if req.RegistryCredential.Password != "registry-secret" || !slices.Contains(req.Secrets, "registry-secret") {
		t.Fatalf("registry credential not wired or not redacted: %+v", req.RegistryCredential)
	}
}

type recordingTrivyRunner struct{ requests []Request }

func (r *recordingTrivyRunner) Name() string { return "trivy" }
func (r *recordingTrivyRunner) Descriptor() Descriptor {
	return Descriptor{Name: "trivy", Phase: PhaseSAST, Weight: WeightLight}
}
func (r *recordingTrivyRunner) Run(_ context.Context, req Request, _ Config, _ EmitFunc) Run {
	r.requests = append(r.requests, req)
	return Run{Scanner: "trivy", Target: req.Target, Status: "completed"}
}

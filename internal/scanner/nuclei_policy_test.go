package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nucleiPolicyRequests covers the typed and legacy paths, with and without a
// crawled endpoint list, that buildNuclei must apply its reviewed policy to.
func nucleiPolicyRequests(t *testing.T) map[string]Request {
	t.Helper()
	return map[string]Request{
		"legacy seed":       {Target: "https://app.example.test/", ScanDir: t.TempDir()},
		"legacy endpoints":  {Target: "https://app.example.test/", ScanDir: t.TempDir(), EndpointTargets: []string{"https://app.example.test/a"}},
		"typed gentle":      {Target: "https://app.example.test/", ScanDir: t.TempDir(), TypedAssessment: true, Profile: ProfileGentle},
		"typed thorough":    {Target: "https://app.example.test/", ScanDir: t.TempDir(), TypedAssessment: true, Profile: ProfileThorough},
		"typed dispatched":  {Target: "https://app.example.test/", ScanDir: t.TempDir(), TypedAssessment: true, StructuredDispatch: true, EndpointTargets: []string{"https://app.example.test/b"}},
		"legacy thorough":   {Target: "https://app.example.test/", ScanDir: t.TempDir(), Profile: ProfileThorough},
		"typed with tmpdir": {Target: "https://app.example.test/", ScanDir: t.TempDir(), TypedAssessment: true},
	}
}

func TestNucleiDefaultPolicyExcludesUnsafeTags(t *testing.T) {
	// Tag names verified against nuclei-templates 8b9d065 (the pinned revision).
	required := []string{
		"dos", "ddos", "fuzz", "fuzzing", "dast", "intrusive", "bruteforce", "default-login", "creds-stuffing",
		"oast", "oob", "interactsh", "rce", "cmdi", "command-injection", "deserialization",
		"file-upload", "fileupload", "upload", "smuggling", "cache-poisoning", "race-condition", "account-takeover",
	}
	for name, req := range nucleiPolicyRequests(t) {
		spec := buildNuclei(req, Config{NucleiPath: "nuclei", NucleiTemplatesDir: "/opt/nuclei-templates", RateRPS: 2})
		got, ok := argValue(spec.args, "-etags")
		if !ok {
			t.Fatalf("%s: -etags missing: %v", name, spec.args)
		}
		tags := strings.Split(got, ",")
		for _, want := range required {
			if !slices.Contains(tags, want) {
				t.Errorf("%s: -etags %q missing %q", name, got, want)
			}
		}
		if got != strings.Join(nucleiExcludedTags, ",") {
			t.Errorf("%s: -etags %q is not the reviewed constant", name, got)
		}
	}
	if nucleiPolicyVersion == "" {
		t.Fatal("nucleiPolicyVersion must be recorded")
	}
}

// Changing the reviewed nuclei policy changes what a stored plan will run, so
// it must ship with a PlanRegistryVersion bump. Update both values together.
func TestNucleiPolicyVersionPinnedToRegistryVersion(t *testing.T) {
	if nucleiPolicyVersion != "1" || nucleiPolicyRegistryVersion != "4" {
		t.Fatalf("nuclei policy %q / registry %q changed: bump PlanRegistryVersion and update this test", nucleiPolicyVersion, nucleiPolicyRegistryVersion)
	}
	if n, err := strconv.Atoi(PlanRegistryVersion); err != nil || n < 4 {
		t.Fatalf("PlanRegistryVersion = %q predates the nuclei policy", PlanRegistryVersion)
	}
}

func TestNucleiProtocolHTTPOnly(t *testing.T) {
	for name, req := range nucleiPolicyRequests(t) {
		spec := buildNuclei(req, Config{NucleiPath: "nuclei", RateRPS: 2})
		if got, ok := argValue(spec.args, "-pt"); !ok || got != "http" {
			t.Errorf("%s: -pt = %q (present %v), want http only: %v", name, got, ok, spec.args)
		}
		if strings.Contains(strings.Join(spec.args, " "), "headless") {
			t.Errorf("%s: headless templates must not be selected: %v", name, spec.args)
		}
	}
}

func TestNucleiLegacyPathAlsoDisablesInteractshAndRedirects(t *testing.T) {
	for name, req := range nucleiPolicyRequests(t) {
		spec := buildNuclei(req, Config{NucleiPath: "nuclei", RateRPS: 2})
		for _, flag := range []string{"-ni", "-dr", "-duc", "-dut"} {
			if !hasArg(spec.args, flag) {
				t.Errorf("%s: missing %s: %v", name, flag, spec.args)
			}
		}
	}
}

func TestNucleiRateAlwaysBoundedIncludingThorough(t *testing.T) {
	for _, rate := range []int{1, 2, 17, 150} {
		for name, req := range nucleiPolicyRequests(t) {
			spec := buildNuclei(req, Config{NucleiPath: "nuclei", RateRPS: rate})
			rl, ok := argValue(spec.args, "-rl")
			if !ok || rl != strconv.Itoa(rate) {
				t.Errorf("%s rate %d: -rl = %q (present %v)", name, rate, rl, ok)
			}
			c, errC := strconv.Atoi(mustArg(t, spec.args, "-c"))
			bs, errBS := strconv.Atoi(mustArg(t, spec.args, "-bs"))
			if errC != nil || errBS != nil || c < 1 || bs < 1 {
				t.Fatalf("%s rate %d: invalid -c/-bs: %v", name, rate, spec.args)
			}
			if c*bs > rate {
				t.Errorf("%s rate %d: -c %d x -bs %d exceeds the rate", name, rate, c, bs)
			}
		}
	}
	// An unset rate never turns into an unlimited scan.
	spec := buildNuclei(Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}, Config{NucleiPath: "nuclei"})
	if rl, ok := argValue(spec.args, "-rl"); !ok || rl == "0" {
		t.Errorf("unset rate produced -rl %q (present %v)", rl, ok)
	}
}

func TestNucleiRetriesAndTimeoutBounded(t *testing.T) {
	for name, req := range nucleiPolicyRequests(t) {
		spec := buildNuclei(req, Config{NucleiPath: "nuclei", RateRPS: 2})
		for flag, want := range map[string]string{"-retries": "1", "-timeout": "10", "-mhe": "3"} {
			if got, ok := argValue(spec.args, flag); !ok || got != want {
				t.Errorf("%s: %s = %q (present %v), want %s", name, flag, got, ok, want)
			}
		}
	}
}

func TestNucleiRunRecordsExcludedCategoriesLimitation(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "nuclei")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ \"$1\" = \"-jle\" ]; then shift; : > \"$1\"; fi; shift; done\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := commandRunner{name: "nuclei", build: buildNuclei}
	req := Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}
	run := runner.Run(context.Background(), req, Config{NucleiPath: bin, RateRPS: 2}, nil)
	if run.Status != "completed" {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
	var excluded, headless *RunLimitation
	for i := range run.Limitations {
		switch run.Limitations[i].Kind {
		case string(GapExcluded):
			excluded = &run.Limitations[i]
		case LimitationHeadlessExcluded:
			headless = &run.Limitations[i]
		}
	}
	if excluded == nil {
		t.Fatalf("missing %s limitation: %+v", GapExcluded, run.Limitations)
	}
	for _, want := range append([]string{"headless", "policy " + nucleiPolicyVersion}, nucleiExcludedTags...) {
		if !strings.Contains(excluded.Reason, want) {
			t.Errorf("excluded limitation %q does not mention %q", excluded.Reason, want)
		}
	}
	if headless == nil {
		t.Errorf("missing %s limitation: %+v", LimitationHeadlessExcluded, run.Limitations)
	}

	// A failed run did not complete, so it reports its failure rather than
	// partial-coverage limitations.
	failBin := filepath.Join(dir, "nuclei-fail")
	if err := os.WriteFile(failBin, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	failed := runner.Run(context.Background(), Request{Target: "https://app.example.test/", ScanDir: t.TempDir()}, Config{NucleiPath: failBin, RateRPS: 2}, nil)
	if failed.Status != "failed" || len(failed.Limitations) != 0 {
		t.Fatalf("failed run = %q with limitations %+v", failed.Status, failed.Limitations)
	}
}

func mustArg(t *testing.T, args []string, flag string) string {
	t.Helper()
	v, ok := argValue(args, flag)
	if !ok {
		t.Fatalf("%s missing: %v", flag, args)
	}
	return v
}

func TestNucleiThoroughHonorsAssessmentDeadline(t *testing.T) {
	budget := NewAssessmentBudget(5, 100, 2*time.Second)
	req := Request{Target: "https://app.example.test/", ScanDir: t.TempDir(), Profile: ProfileThorough}
	spec := buildNuclei(req, Config{NucleiPath: "nuclei", NucleiTimeout: time.Minute, Budget: budget})
	if spec.notApp != "" || spec.timeout <= 0 || spec.timeout > 2*time.Second {
		t.Fatalf("thorough nuclei did not inherit assessment deadline: notApp=%q timeout=%s", spec.notApp, spec.timeout)
	}
}

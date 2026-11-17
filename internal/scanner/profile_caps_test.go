package scanner

import (
	"testing"
	"time"
)

// web-max promises no per-scanner time cap and parameter mining, exactly like
// web-thorough. Before this, nothing outside profile.go read ProfileMax.
func TestWebMaxLiftsScannerTimeCapsLikeThorough(t *testing.T) {
	for _, profile := range []string{ProfileThorough, ProfileMax} {
		if !profileLiftsTimeCaps(profile) {
			t.Errorf("%s must lift time caps", profile)
		}
		nikto := buildNikto(Request{Target: "http://example.test/", ScanDir: t.TempDir(), Profile: profile}, Config{NiktoPath: "nikto", NiktoTimeout: time.Second})
		if nikto.timeout != 0 {
			t.Errorf("%s nikto timeout=%s, want none", profile, nikto.timeout)
		}
		nuclei := buildNuclei(Request{Target: "https://example.test/", ScanDir: t.TempDir(), TypedAssessment: true, Profile: profile}, Config{NucleiPath: "nuclei", NucleiTimeout: time.Hour})
		if nuclei.notApp != "" || nuclei.timeout != 0 {
			t.Errorf("%s nuclei timeout=%s notApp=%q, want none", profile, nuclei.timeout, nuclei.notApp)
		}
		testssl := buildTestssl(Request{Target: "https://app.test/", ScanDir: t.TempDir(), Profile: profile, AppScope: scopeFor(t, "https://app.test/")}, Config{TestsslPath: "testssl.sh", TestsslTimeout: time.Hour})
		if testssl.notApp != "" || testssl.timeout != 0 {
			t.Errorf("%s testssl timeout=%s notApp=%q, want none", profile, testssl.timeout, testssl.notApp)
		}
		dalfox := buildDalfox(Request{Target: "https://app.test/", ScanDir: t.TempDir(), WebEndpoints: []string{"https://app.test/s?q=1"}, Profile: profile}, Config{DalfoxPath: "dalfox"})
		if dalfox.timeout < uncappedToolMaxDuration {
			t.Errorf("%s dalfox timeout=%s, want the uncapped ceiling %s", profile, dalfox.timeout, uncappedToolMaxDuration)
		}
		if hasArg(dalfox.args, "--skip-mining-all") {
			t.Errorf("%s dalfox must mine parameters: %v", profile, dalfox.args)
		}
	}
	for _, profile := range []string{"", ProfileGentle, ProfileNextjsDeep} {
		if profileLiftsTimeCaps(profile) {
			t.Errorf("profile %q must keep time caps", profile)
		}
		dalfox := buildDalfox(Request{Target: "https://app.test/", ScanDir: t.TempDir(), WebEndpoints: []string{"https://app.test/s?q=1"}, Profile: profile}, Config{DalfoxPath: "dalfox"})
		if dalfox.timeout != dalfoxMaxDuration {
			t.Errorf("profile %q dalfox timeout=%s, want %s", profile, dalfox.timeout, dalfoxMaxDuration)
		}
	}
}

func TestBoundedToolDuration(t *testing.T) {
	cases := []struct {
		configured, ceiling time.Duration
		profile             string
		want                time.Duration
	}{
		{0, 15 * time.Minute, ProfileGentle, 15 * time.Minute},
		{time.Hour, 15 * time.Minute, ProfileGentle, 15 * time.Minute},
		{time.Minute, 15 * time.Minute, ProfileGentle, time.Minute},
		{0, 15 * time.Minute, ProfileMax, uncappedToolMaxDuration},
		{time.Hour, 15 * time.Minute, ProfileMax, time.Hour},
		{time.Minute, 15 * time.Minute, ProfileThorough, time.Minute},
	}
	for _, c := range cases {
		if got := boundedToolDuration(c.configured, c.ceiling, c.profile); got != c.want {
			t.Errorf("boundedToolDuration(%s,%s,%q)=%s want %s", c.configured, c.ceiling, c.profile, got, c.want)
		}
	}
}

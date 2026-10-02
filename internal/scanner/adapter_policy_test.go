package scanner

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestAdapterPolicyRestriction(t *testing.T) {
	exclusions := []assessment.Exclusion{{PathPattern: "/logout"}}
	for _, tc := range []struct {
		name       string
		id         string
		cfg        assessment.AssessmentConfig
		restricted bool
	}{
		{"wapiti default policy", "wapiti", assessment.AssessmentConfig{}, true},
		{"wapiti test environment", "wapiti", assessment.AssessmentConfig{TestEnvironment: true}, false},
		{"wapiti test environment with exclusions", "wapiti", assessment.AssessmentConfig{TestEnvironment: true, Exclusions: exclusions}, false},
		{"nikto without exclusions", "nikto", assessment.AssessmentConfig{}, false},
		{"nikto with exclusions", "nikto", assessment.AssessmentConfig{Exclusions: exclusions}, true},
		{"nikto with exclusions in a test environment", "nikto", assessment.AssessmentConfig{TestEnvironment: true, Exclusions: exclusions}, true},
		{"dalfox is never restricted", "dalfox", assessment.AssessmentConfig{Exclusions: exclusions}, false},
		{"other scanners are untouched", "nuclei", assessment.AssessmentConfig{Exclusions: exclusions}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restricted, reason := AdapterPolicyRestriction(tc.id, tc.cfg)
			if restricted != tc.restricted {
				t.Fatalf("restricted = %v (%q), want %v", restricted, reason, tc.restricted)
			}
			if restricted && reason == "" {
				t.Fatal("a restriction must carry a visible reason")
			}
			if !restricted && reason != "" {
				t.Fatalf("unrestricted adapter carries reason %q", reason)
			}
		})
	}
}

// The runtime check on a Request agrees with the plan-time check on the
// config the Request was derived from.
func TestRequestPolicyRestrictionMatchesConfig(t *testing.T) {
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{{Scheme: "https", Host: "app.test", PathPrefix: "/"}}, assessment.Exclusion{PathPattern: "/logout"})
	if restricted, _ := requestPolicyRestriction("nikto", Request{AppScope: &scope}); !restricted {
		t.Fatal("nikto must be restricted when the request scope carries exclusions")
	}
	if restricted, _ := requestPolicyRestriction("nikto", Request{}); restricted {
		t.Fatal("legacy nikto request (nil scope) must stay unrestricted")
	}
	if restricted, _ := requestPolicyRestriction("wapiti", Request{}); !restricted {
		t.Fatal("wapiti must be restricted outside a test environment")
	}
	if restricted, _ := requestPolicyRestriction("wapiti", Request{TestEnvironment: true}); restricted {
		t.Fatal("wapiti must run in a declared test environment")
	}
}

package scanner

import (
	"strings"
	"testing"
)

func TestCompareSemverPrecedence(t *testing.T) {
	ordered := []string{"14.2.3-canary.9", "14.2.3-canary.10", "14.2.3-rc.1", "14.2.3", "14.2.10", "15.0.0-beta.0", "15.0.0", "v15.0.1+build.5"}
	for i := 0; i+1 < len(ordered); i++ {
		if cmp, ok := compareSemver(ordered[i], ordered[i+1]); !ok || cmp >= 0 {
			t.Fatalf("%s should sort before %s (cmp=%d ok=%v)", ordered[i], ordered[i+1], cmp, ok)
		}
	}
	if cmp, ok := compareSemver("13.0", "13.0.0"); !ok || cmp != 0 {
		t.Fatalf("short bound 13.0 != 13.0.0 (cmp=%d ok=%v)", cmp, ok)
	}
	for _, bad := range []string{"", "14.2.x", "14.2.3.4", "14.2.3-", "latest", "-1.0.0"} {
		if _, ok := parseSemver(bad); ok {
			t.Fatalf("%q parsed as a version", bad)
		}
	}
}

func TestSemverInRange(t *testing.T) {
	for _, tc := range []struct {
		version, expr string
		want          bool
	}{
		{"14.1.0", ">= 10.0.0, < 15.5.24", true},
		{"15.5.24", ">= 10.0.0, < 15.5.24", false},
		{"16.4.0", ">= 16.0.0, <= 16.4.0", true},
		{"16.4.1", ">= 16.0.0, <= 16.4.0", false},
		{"15.6.0-canary.30", ">= 10.0.0, < 15.5.10", false},
		{"15.6.0-canary.30", ">= 15.6.0-canary.0, < 15.6.0-canary.61", true},
		{"15.6.0-canary.61", ">= 15.6.0-canary.0, < 15.6.0-canary.61", false},
		{"13.0.0", "= 13.0.0", true},
		{"13.0.0", ">= nonsense", false},
		{"14.2.29", ">= 13.0, < 14.2.30", true},
		{"12.9.9", ">= 13.0, < 14.2.30", false},
	} {
		if got := semverInRange(tc.version, tc.expr); got != tc.want {
			t.Fatalf("semverInRange(%q, %q) = %v", tc.version, tc.expr, got)
		}
	}
}

func TestNextjsAdvisorySnapshotLoadsAndMatches(t *testing.T) {
	snapshot, err := loadNextjsAdvisories()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Advisories) == 0 || snapshot.Retrieved == "" || !strings.HasPrefix(snapshot.Source, "https://api.github.com/advisories") {
		t.Fatalf("snapshot metadata = %q %q %d", snapshot.Source, snapshot.Retrieved, len(snapshot.Advisories))
	}
	for _, a := range snapshot.Advisories {
		if !strings.HasPrefix(a.GHSAID, "GHSA-") || len(a.Ranges) == 0 || a.URL == "" {
			t.Fatalf("incomplete advisory %+v", a)
		}
		switch a.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Fatalf("%s severity %q", a.GHSAID, a.Severity)
		}
		for _, r := range a.Ranges {
			// Every range in the snapshot must be understood by the matcher:
			// its own bounds evaluate without a parse failure.
			for _, part := range strings.Split(r.Range, ",") {
				bound := strings.TrimLeft(strings.TrimSpace(part), "<>= ")
				if _, ok := parseSemver(bound); !ok {
					t.Fatalf("%s: unparseable bound %q in %q", a.GHSAID, bound, r.Range)
				}
			}
		}
	}
	old := matchNextjsAdvisories(snapshot, "14.1.0")
	if len(old) == 0 {
		t.Fatal("an old release matched no advisories")
	}
	for _, m := range old {
		if !semverInRange("14.1.0", m.Range.Range) {
			t.Fatalf("%s matched outside %q", m.Advisory.GHSAID, m.Range.Range)
		}
	}
	if got := matchNextjsAdvisories(snapshot, "not-a-version"); got != nil {
		t.Fatalf("garbage version matched %d advisories", len(got))
	}
}

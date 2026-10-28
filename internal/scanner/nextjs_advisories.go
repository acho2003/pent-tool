package scanner

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

// nextjsAdvisoriesJSON is a reviewed snapshot of GitHub's advisory database for
// the npm package "next". Refresh it with runtime/update-nextjs-advisories.py
// and bump nextjsAdvisoriesVersion in the same commit.
//
//go:embed nextjs_advisories.json
var nextjsAdvisoriesJSON []byte

const nextjsAdvisoriesVersion = "github-advisories-2026-10-28"

type nextjsAdvisory struct {
	GHSAID    string                `json:"ghsa_id"`
	CVEID     string                `json:"cve_id"`
	Severity  string                `json:"severity"`
	Summary   string                `json:"summary"`
	URL       string                `json:"url"`
	CWEs      []string              `json:"cwes"`
	Published string                `json:"published"`
	Ranges    []nextjsAdvisoryRange `json:"ranges"`
}

type nextjsAdvisoryRange struct {
	Range   string `json:"range"`
	Patched string `json:"patched"`
}

type nextjsAdvisorySnapshot struct {
	Source     string           `json:"source"`
	Retrieved  string           `json:"retrieved"`
	Advisories []nextjsAdvisory `json:"advisories"`
}

var loadNextjsAdvisories = sync.OnceValues(func() (nextjsAdvisorySnapshot, error) {
	var snapshot nextjsAdvisorySnapshot
	err := json.Unmarshal(nextjsAdvisoriesJSON, &snapshot)
	return snapshot, err
})

// nextjsAdvisoryMatch is one advisory whose affected range contains a version.
type nextjsAdvisoryMatch struct {
	Advisory nextjsAdvisory
	Range    nextjsAdvisoryRange
}

// matchNextjsAdvisories returns the advisories whose affected ranges contain
// version. An unparseable version matches nothing.
func matchNextjsAdvisories(snapshot nextjsAdvisorySnapshot, version string) []nextjsAdvisoryMatch {
	if _, ok := parseSemver(version); !ok {
		return nil
	}
	var out []nextjsAdvisoryMatch
	for _, advisory := range snapshot.Advisories {
		for _, r := range advisory.Ranges {
			if semverInRange(version, r.Range) {
				out = append(out, nextjsAdvisoryMatch{Advisory: advisory, Range: r})
				break
			}
		}
	}
	return out
}

// semverInRange evaluates a GitHub advisory range: comma-separated
// comparators (>=, >, <=, <, =) that must all hold. Any comparator that cannot
// be parsed makes the range not match rather than guess.
func semverInRange(version, expr string) bool {
	parts := strings.Split(expr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		op := "="
		for _, candidate := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(part, candidate) {
				op, part = candidate, strings.TrimSpace(part[len(candidate):])
				break
			}
		}
		cmp, ok := compareSemver(version, part)
		if !ok {
			return false
		}
		switch op {
		case ">=":
			ok = cmp >= 0
		case ">":
			ok = cmp > 0
		case "<=":
			ok = cmp <= 0
		case "<":
			ok = cmp < 0
		default:
			ok = cmp == 0
		}
		if !ok {
			return false
		}
	}
	return len(parts) > 0
}

type semver struct {
	core [3]int
	pre  []string
}

func parseSemver(raw string) (semver, bool) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		raw = raw[:i]
	}
	var v semver
	core, pre, hasPre := strings.Cut(raw, "-")
	// Advisory bounds sometimes omit trailing components ("13.0"); they
	// default to zero.
	fields := strings.Split(core, ".")
	if len(fields) > 3 {
		return v, false
	}
	for i, field := range fields {
		n, err := strconv.Atoi(field)
		if err != nil || n < 0 {
			return v, false
		}
		v.core[i] = n
	}
	if hasPre {
		if pre == "" {
			return v, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// compareSemver orders two versions by Semantic Versioning 2.0 precedence:
// a prerelease sorts before its release, numeric identifiers compare
// numerically and sort before alphanumeric ones.
func compareSemver(a, b string) (int, bool) {
	va, okA := parseSemver(a)
	vb, okB := parseSemver(b)
	if !okA || !okB {
		return 0, false
	}
	for i := range va.core {
		if va.core[i] != vb.core[i] {
			return compareInts(va.core[i], vb.core[i]), true
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0, true
	case len(va.pre) == 0:
		return 1, true
	case len(vb.pre) == 0:
		return -1, true
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		x, y := va.pre[i], vb.pre[i]
		nx, errX := strconv.Atoi(x)
		ny, errY := strconv.Atoi(y)
		switch {
		case errX == nil && errY == nil:
			if nx != ny {
				return compareInts(nx, ny), true
			}
		case errX == nil:
			return -1, true
		case errY == nil:
			return 1, true
		case x != y:
			return strings.Compare(x, y), true
		}
	}
	return compareInts(len(va.pre), len(vb.pre)), true
}

func compareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

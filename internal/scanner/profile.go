package scanner

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	ProfileNextjsDeep = "nextjs-deep"
	ProfileGentle     = "web-gentle"
	ProfileThorough   = "web-thorough"
)

type WebProfile struct {
	Name               string        `json:"name"`
	RateRPS            int           `json:"rate_rps"`
	MaxEndpoints       int           `json:"max_endpoints"`
	Budget             time.Duration `json:"budget"`
	Browser            bool          `json:"browser"`
	AllowStateChanging bool          `json:"allow_state_changing"`
}

func DefaultWebProfile(name string) WebProfile {
	if name == ProfileNextjsDeep {
		// Tuned for a thorough authorized scan of one's own application: enough
		// request rate and time for the active scanners (nuclei, nikto, dalfox,
		// zap) to finish, not only the fast passive checks. Still finite and
		// never state-changing. Operators tune rate/budget/endpoints per
		// engagement with the XALGORIX_WEB_* overrides below.
		return WebProfile{Name: ProfileNextjsDeep, RateRPS: 50, MaxEndpoints: 3000, Budget: 240 * time.Minute, Browser: true, AllowStateChanging: false}
	}
	if name == ProfileThorough {
		return WebProfile{Name: ProfileThorough, RateRPS: 150, MaxEndpoints: 2000, Budget: 0, Browser: true, AllowStateChanging: false}
	}
	return WebProfile{Name: ProfileGentle, RateRPS: 2, MaxEndpoints: 500, Budget: 30 * time.Minute, Browser: true, AllowStateChanging: false}
}

func ResolveWebProfile(name string) (WebProfile, bool) {
	if name == "" {
		name = ProfileGentle
	}
	if name != ProfileGentle && name != ProfileThorough && name != ProfileNextjsDeep {
		return WebProfile{}, false
	}
	return applyWebProfileOverrides(DefaultWebProfile(name)), true
}

// applyWebProfileOverrides lets an operator tune the active web profile for an
// authorized engagement without a rebuild. Each override is optional; an unset
// or invalid value leaves the profile default in place. A budget of 0 minutes
// means no time cap. These apply to whichever profile is resolved, so the
// operator can raise the rate and budget on their own authorized targets.
func applyWebProfileOverrides(p WebProfile) WebProfile {
	// Rate may be explicitly 0, which means no limit / full speed: the request
	// limiter is disabled and ZAP keeps its daemon-default active-scan concurrency
	// with no injected delay. Parsed as non-negative, like the budget below.
	if raw := strings.TrimSpace(os.Getenv("XALGORIX_WEB_RATE_RPS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			p.RateRPS = n
		}
	}
	if v, ok := positiveEnvInt("XALGORIX_WEB_MAX_ENDPOINTS"); ok {
		p.MaxEndpoints = v
	}
	// Budget may be explicitly 0 (unlimited), so it is parsed separately from the
	// strictly-positive overrides above.
	if raw := strings.TrimSpace(os.Getenv("XALGORIX_WEB_BUDGET_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			p.Budget = time.Duration(n) * time.Minute
		}
	}
	return p
}

// positiveEnvInt reads a strictly-positive integer from an environment variable.
func positiveEnvInt(name string) (int, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

package scanner

import "time"

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
		return WebProfile{Name: ProfileNextjsDeep, RateRPS: 10, MaxEndpoints: 3000, Budget: 90 * time.Minute, Browser: true, AllowStateChanging: false}
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
	return DefaultWebProfile(name), true
}

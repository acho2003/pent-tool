package scanner

import "time"

const (
	ProfileGentle   = "web-gentle"
	ProfileThorough = "web-thorough"
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
	if name == ProfileThorough {
		return WebProfile{Name: ProfileThorough, RateRPS: 5, MaxEndpoints: 2000, Budget: 120 * time.Minute, Browser: true, AllowStateChanging: false}
	}
	return WebProfile{Name: ProfileGentle, RateRPS: 2, MaxEndpoints: 500, Budget: 30 * time.Minute, Browser: true, AllowStateChanging: false}
}

func ResolveWebProfile(name string) (WebProfile, bool) {
	if name == "" {
		name = ProfileGentle
	}
	if name != ProfileGentle && name != ProfileThorough {
		return WebProfile{}, false
	}
	return DefaultWebProfile(name), true
}

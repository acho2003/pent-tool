package credentials

import (
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"strings"
)

// BrowserStorage is encrypted with its target-bound credential. It is never
// returned in credential metadata or copied to an assessment's public config.
type BrowserStorage struct {
	Local   map[string]string `json:"local,omitempty"`
	Session map[string]string `json:"session,omitempty"`
}

func (s *BrowserStorage) Validate() error {
	if s == nil {
		return nil
	}
	count, size := 0, 0
	for _, values := range []map[string]string{s.Local, s.Session} {
		for key, value := range values {
			count++
			size += len(key) + len(value)
			if strings.TrimSpace(key) == "" || strings.ContainsRune(key, '\x00') {
				return fmt.Errorf("browser storage keys must be nonempty")
			}
		}
	}
	if count == 0 || count > 128 || size > 32<<10 {
		return fmt.Errorf("browser storage must contain 1–128 entries totaling at most 32768 bytes")
	}
	return nil
}

func validateBrowserRecord(record Record) error {
	if record.BrowserStorage == nil {
		return nil
	}
	switch record.Kind {
	case assessment.AccessApplicationHeaders, assessment.AccessApplicationCookies, assessment.AccessBearerToken, assessment.AccessAPIKey, assessment.AccessFormLogin:
		return nil
	default:
		return fmt.Errorf("browser storage requires an application credential")
	}
}

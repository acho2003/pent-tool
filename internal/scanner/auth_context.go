package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"github.com/xalgord/xalgorix/v4/internal/credentials"
)

// AuthContext describes a verified target-bound identity. Secrets and session
// renewal callbacks exist only during execution, never in persisted plans.
type AuthContext struct {
	ID             string                                            `json:"id"`
	TargetID       string                                            `json:"target_id"`
	Identity       string                                            `json:"identity,omitempty"`
	Role           string                                            `json:"role,omitempty"`
	Primary        bool                                              `json:"primary"`
	State          assessment.EvidenceState                          `json:"state"`
	Reason         string                                            `json:"reason,omitempty"`
	Headers        []string                                          `json:"-"`
	Refresh        func(context.Context, []string) ([]string, error) `json:"-"`
	BrowserStorage *credentials.BrowserStorage                       `json:"-"`
}

func AuthenticationContextID(targetID, identity string) string {
	sum := sha256.Sum256([]byte(targetID + "\x00" + strings.TrimSpace(identity)))
	return hex.EncodeToString(sum[:12])
}

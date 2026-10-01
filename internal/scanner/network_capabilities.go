package scanner

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	capNetAdmin = 12
	capNetRaw   = 13
)

// MasscanCapabilityReason is empty only when this process has the Linux
// capabilities required by Xalgorix's raw-packet Masscan adapter.
func MasscanCapabilityReason() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "Masscan raw-packet capability check could not read /proc/self/status"
	}
	return masscanCapabilityReason(string(status))
}

func masscanCapabilityReason(status string) string {
	var effective uint64
	found := false
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
			var err error
			effective, err = strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil {
				return "Masscan raw-packet capability check could not parse CapEff"
			}
			found = true
			break
		}
	}
	if !found {
		return "Masscan raw-packet capability check found no CapEff"
	}
	var missing []string
	if effective&(1<<capNetAdmin) == 0 {
		missing = append(missing, "NET_ADMIN")
	}
	if effective&(1<<capNetRaw) == 0 {
		missing = append(missing, "NET_RAW")
	}
	if len(missing) > 0 {
		return fmt.Sprintf("Masscan raw-packet scan requires %s; use the explicit network capability override", strings.Join(missing, " and "))
	}
	return ""
}

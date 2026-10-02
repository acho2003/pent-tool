package web

import "strings"

const (
	activityModeActive  = "active"
	activityModePassive = "passive"
)

func normalizeActivityMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case activityModePassive:
		return activityModePassive
	default:
		return activityModeActive
	}
}

func normalizeScanRequestActivity(req *ScanRequest) {
	if req == nil {
		return
	}
	req.ReconMode = normalizeActivityMode(req.ReconMode)
	req.ScanIntensity = normalizeActivityMode(req.ScanIntensity)
	if req.ScanIntensity == activityModePassive {
		req.ReconMode = activityModePassive
	}
}

func normalizeScheduleActivity(sch *ScanSchedule) {
	if sch == nil {
		return
	}
	sch.ReconMode = normalizeActivityMode(sch.ReconMode)
	sch.ScanIntensity = normalizeActivityMode(sch.ScanIntensity)
	if sch.ScanIntensity == activityModePassive {
		sch.ReconMode = activityModePassive
	}
}

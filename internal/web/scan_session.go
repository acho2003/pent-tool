package web

// executeScanSession runs a single scan in complete isolation via the
// deterministic scanner pipeline.
func (s *Server) executeScanSession(sess *scanSession) {
	s.executeDeterministicScanSession(sess)
}

func firstSelectedPhase(phases []int) int {
	if len(phases) == 0 {
		return 1
	}
	first := 0
	for _, phase := range phases {
		if phase < 1 || phase > 22 {
			continue
		}
		if first == 0 || phase < first {
			first = phase
		}
	}
	if first == 0 {
		return 1
	}
	return first
}

func phaseAllowed(phases []int, phase int) bool {
	if phase < 1 || phase > 22 {
		return false
	}
	if len(phases) == 0 {
		return true
	}
	for _, allowed := range phases {
		if allowed == phase {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

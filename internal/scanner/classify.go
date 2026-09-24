package scanner

import "strings"

// isWebPort reports whether an open port is an HTTP(S) service, by well-known
// port number or by nmap-detected service name.
func isWebPort(p Port) bool {
	switch p.Number {
	case 80, 443, 8080, 8443:
		return true
	}
	return strings.Contains(strings.ToLower(p.Service), "http")
}

// Classify deterministically assigns WEB and/or SERVER tracks to a host from its
// recon evidence. WEB when it serves HTTP(S) (a live URL, TLS, or a web-ish open
// port). SERVER when any non-web service port is open. A host can be both; a live
// host exposing nothing useful is neither.
func Classify(ev HostEvidence) []Track {
	web := ev.TLS || len(ev.LiveURLs) > 0
	server := false
	for _, p := range ev.OpenPorts {
		if isWebPort(p) {
			web = true
		} else {
			server = true
		}
	}
	var out []Track
	if web {
		out = append(out, TrackWeb)
	}
	if server {
		out = append(out, TrackServer)
	}
	return out
}

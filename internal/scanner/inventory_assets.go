package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
	"net/url"
	"strings"
)

type InventoryHost struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	Addresses   []string `json:"addresses,omitempty"`
	State       string   `json:"state"`
	Source      string   `json:"source"`
	EvidenceRef string   `json:"evidence_reference,omitempty"`
}
type InventoryService struct {
	ID          string `json:"id"`
	HostID      string `json:"host_id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Origin      string `json:"origin,omitempty"`
	TLS         bool   `json:"tls,omitempty"`
	State       string `json:"state"`
	EvidenceRef string `json:"evidence_reference,omitempty"`
}
type InventoryDefinition struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	URL         string `json:"url,omitempty"`
	State       string `json:"state"`
	EvidenceRef string `json:"evidence_reference,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

func inventoryID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:12])
}

func MergeRunAssets(surface *AttackSurface, run Run) {
	if surface == nil {
		return
	}
	addHost := func(host, state string, addresses []string) string {
		id := inventoryID("host", strings.ToLower(host))
		for i := range surface.Hosts {
			h := &surface.Hosts[i]
			if h.ID == id {
				h.Addresses = mergeStrings(h.Addresses, addresses)
				if state != "candidate" {
					h.State = state
				}
				return id
			}
		}
		surface.Hosts = append(surface.Hosts, InventoryHost{ID: id, Host: host, State: state, Addresses: addresses, Source: run.Scanner, EvidenceRef: run.ArtifactPath})
		return id
	}
	for _, host := range run.CandidateHosts {
		addHost(host, "candidate", nil)
	}
	if run.DNSResolution != nil {
		addHost(run.DNSResolution.Host, "resolved", append(append([]string{}, run.DNSResolution.A...), run.DNSResolution.AAAA...))
	}
	for _, o := range run.HTTPObservations {
		u, err := url.Parse(o.URL)
		if err != nil || u.Host == "" {
			continue
		}
		hostID := addHost(u.Hostname(), "observed", nil)
		origin, err := assessment.ParseApprovedOrigin("", o.URL)
		if err != nil {
			continue
		}
		id := inventoryID("service", origin.Host, origin.Origin())
		exists := false
		for _, s := range surface.Services {
			if s.ID == id {
				exists = true
			}
		}
		if !exists {
			surface.Services = append(surface.Services, InventoryService{ID: id, HostID: hostID, Host: origin.Host, Port: origin.Port, Protocol: "tcp", Origin: origin.Origin(), TLS: origin.Scheme == "https", State: "live", EvidenceRef: run.ArtifactPath})
		}
	}
}

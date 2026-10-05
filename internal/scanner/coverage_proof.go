package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
)

type ScannerProof struct {
	Scanner        string `json:"scanner"`
	Selected       int    `json:"selected"`
	Submitted      int    `json:"submitted"`
	Acknowledged   int    `json:"acknowledged"`
	Exercised      *int   `json:"exercised"`
	BatchCompleted int    `json:"batch_completed"`
	Failed         int    `json:"failed"`
	Skipped        int    `json:"skipped"`
	Unknown        int    `json:"unknown"`
}
type CoverageProof struct {
	ExpandedEnabled  bool                  `json:"expanded_enabled"`
	Discovered       int                   `json:"discovered"`
	Seeds            int                   `json:"seeds"`
	Candidates       int                   `json:"candidates"`
	Hosts            int                   `json:"hosts"`
	Services         int                   `json:"services"`
	TLS              int                   `json:"tls_services"`
	Forms            int                   `json:"forms"`
	Parameterized    int                   `json:"parameterized"`
	ObservedWithAuth int                   `json:"observed_with_auth"`
	Definitions      []InventoryDefinition `json:"definitions"`
	Scanners         []ScannerProof        `json:"scanners"`
	NotTracked       []string              `json:"not_tracked"`
	DiscoveryGaps    []string              `json:"discovery_gaps"`
}

func ReadCoverageEvents(path string) ([]CoverageEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []CoverageEvent
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		var e CoverageEvent
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			return events, err
		}
		events = append(events, e)
	}
	return events, s.Err()
}
func BuildCoverageProof(surfaces []AttackSurface, runs []Run) CoverageProof {
	proof := CoverageProof{ExpandedEnabled: UnifiedWorkflowEnabled(), Definitions: []InventoryDefinition{}, Scanners: []ScannerProof{}, NotTracked: []string{"parameters_tested", "templates_executed", "protected_route_coverage_percent"}}
	type sets struct {
		selected, submitted, ack, exercised, batch, failed, skipped map[string]bool
		recorded                                                    bool
	}
	states := map[string]*sets{}
	get := func(name string) *sets {
		if states[name] == nil {
			states[name] = &sets{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, false}
		}
		return states[name]
	}
	hosts, services := map[string]bool{}, map[string]bool{}
	for _, surface := range surfaces {
		proof.Discovered += len(surface.Endpoints)
		proof.Definitions = append(proof.Definitions, surface.Definitions...)
		proof.DiscoveryGaps = append(proof.DiscoveryGaps, surface.DiscoveryGaps...)
		for _, h := range surface.Hosts {
			if h.State == "candidate" {
				proof.Candidates++
			} else {
				hosts[h.ID] = true
			}
		}
		for _, s := range surface.Services {
			if !services[s.ID] {
				services[s.ID] = true
				if s.TLS {
					proof.TLS++
				}
			}
		}
		for _, e := range surface.Endpoints {
			if e.ObservationKind == "seed" {
				proof.Seeds++
			}
			if e.HasForm {
				proof.Forms++
			}
			if e.HasParameters {
				proof.Parameterized++
			}
			if e.ObservedWithAuth {
				proof.ObservedWithAuth++
			}
			for _, c := range e.ScannerCoverage {
				state := get(c.Scanner)
				key := surface.Scope + ":" + e.ID
				switch c.Status {
				case "dispatched":
					state.selected[key] = true
				case EndpointCoverageBatchCompleted:
					state.selected[key], state.batch[key] = true, true
				case "failed":
					state.selected[key], state.failed[key] = true, true
				case "skipped":
					state.skipped[key] = true
				}
			}
		}
	}
	proof.Hosts, proof.Services = len(hosts), len(services)
	for _, run := range runs {
		state := get(run.Scanner)
		data, err := os.ReadFile(run.InputManifestPath)
		if err == nil {
			var manifest ScannerInputManifest
			if json.Unmarshal(data, &manifest) == nil {
				for _, r := range manifest.Requests {
					key := run.Scope + ":" + r.EndpointID
					if r.Selected {
						state.selected[key] = true
					} else {
						state.skipped[key] = true
					}
				}
			}
		}
		for _, s := range run.Submissions {
			if s.EndpointID == "" {
				continue
			}
			key := run.Scope + ":" + s.EndpointID
			switch s.Status {
			case "submitted":
				state.submitted[key] = true
			case "acknowledged":
				state.submitted[key], state.ack[key] = true, true
			case "failed":
				state.failed[key] = true
			case "skipped":
				state.skipped[key] = true
			}
		}
		if events, err := ReadCoverageEvents(run.CoverageEventsPath); err == nil {
			state.recorded = true
			for _, e := range events {
				for _, id := range e.EndpointIDs {
					key := run.Scope + ":" + id
					switch e.Kind {
					case "submitted":
						state.submitted[key] = true
					case "observed":
						if e.Phase == "active_test" {
							state.exercised[key] = true
						}
					case "failed":
						state.failed[key] = true
					}
				}
			}
		}
	}
	names := make([]string, 0, len(states))
	for name := range states {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		state := states[name]
		row := ScannerProof{Scanner: name, Selected: len(state.selected), Submitted: len(state.submitted), Acknowledged: len(state.ack), BatchCompleted: len(state.batch), Failed: len(state.failed), Skipped: len(state.skipped), Unknown: len(state.selected)}
		if state.recorded {
			n := len(state.exercised)
			row.Exercised = &n
			row.Unknown -= n
			if row.Unknown < 0 {
				row.Unknown = 0
			}
		}
		proof.Scanners = append(proof.Scanners, row)
	}
	return proof
}

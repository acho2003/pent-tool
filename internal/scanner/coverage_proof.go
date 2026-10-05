package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"time"
)

type ScannerProof struct {
	Completed        *int   `json:"completed"`
	EnabledTemplates *int   `json:"enabled_templates"`
	Scanner          string `json:"scanner"`
	Selected         int    `json:"selected"`
	Submitted        int    `json:"submitted"`
	Acknowledged     int    `json:"acknowledged"`
	Exercised        *int   `json:"exercised"`
	BatchCompleted   int    `json:"batch_completed"`
	Failed           int    `json:"failed"`
	Skipped          int    `json:"skipped"`
	Unknown          int    `json:"unknown"`
}
type ProofItem struct {
	ID          string `json:"id"`
	EndpointID  string `json:"endpoint_id,omitempty"`
	Scope       string `json:"scope,omitempty"`
	URL         string `json:"url,omitempty"`
	Method      string `json:"method,omitempty"`
	State       string `json:"state,omitempty"`
	Reason      string `json:"reason,omitempty"`
	EvidenceRef string `json:"evidence_reference,omitempty"`
	AttemptID   string `json:"attempt_id,omitempty"`
}
type CoverageProof struct {
	Items            map[string][]ProofItem `json:"-"`
	ExpandedEnabled  bool                   `json:"expanded_enabled"`
	Approved         int                    `json:"approved"`
	Eligible         int                    `json:"eligible"`
	Observed         int                    `json:"observed"`
	Discovered       int                    `json:"discovered"`
	Seeds            int                    `json:"seeds"`
	Candidates       int                    `json:"candidates"`
	Hosts            int                    `json:"hosts"`
	Services         int                    `json:"services"`
	TLS              int                    `json:"tls_services"`
	Forms            int                    `json:"forms"`
	Parameterized    int                    `json:"parameterized"`
	ObservedWithAuth int                    `json:"observed_with_auth"`
	Definitions      []InventoryDefinition  `json:"definitions"`
	Scanners         []ScannerProof         `json:"scanners"`
	NotTracked       []string               `json:"not_tracked"`
	DiscoveryGaps    []string               `json:"discovery_gaps"`
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
	proof := CoverageProof{Items: map[string][]ProofItem{}, Definitions: []InventoryDefinition{}, Scanners: []ScannerProof{}, NotTracked: []string{"parameters_tested", "templates_executed", "protected_route_coverage_percent"}}
	type sets struct {
		selected, submitted, ack, exercised, batch, failed, skipped map[string]bool
		recorded                                                    bool
		enabled                                                     *int
	}
	states := map[string]*sets{}
	get := func(name string) *sets {
		if states[name] == nil {
			states[name] = &sets{map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, false, nil}
		}
		return states[name]
	}
	lookup := map[string]ProofItem{}
	scannerLookup := map[string]ProofItem{}
	addItem := func(metric string, item ProofItem) { proof.Items[metric] = append(proof.Items[metric], item) }
	hosts, services := map[string]bool{}, map[string]bool{}
	for _, surface := range surfaces {
		expanded := surface.WorkflowVersion == "unified-v1"
		proof.ExpandedEnabled = proof.ExpandedEnabled || expanded
		if surface.ClassifierVersion < 5 {
			if !slices.Contains(proof.NotTracked, "historical_encoded_query_identity") {
				proof.NotTracked = append(proof.NotTracked, "historical_encoded_query_identity")
			}
		}
		proof.Discovered += len(surface.Endpoints)
		proof.Definitions = append(proof.Definitions, surface.Definitions...)
		proof.DiscoveryGaps = append(proof.DiscoveryGaps, surface.DiscoveryGaps...)
		for _, h := range surface.Hosts {
			item := ProofItem{ID: h.ID, URL: h.Host, State: h.State, EvidenceRef: h.EvidenceRef}
			if h.State == "candidate" {
				proof.Candidates++
				addItem("candidates", item)
			} else {
				if !hosts[h.ID] {
					addItem("hosts", item)
				}
				hosts[h.ID] = true
			}
		}
		for _, s := range surface.Services {
			if !services[s.ID] {
				services[s.ID] = true
				item := ProofItem{ID: s.ID, URL: s.Origin, State: s.State, EvidenceRef: s.EvidenceRef, Reason: fmt.Sprintf("%s %s:%d", s.Protocol, s.Host, s.Port)}
				addItem("services", item)
				if s.TLS {
					addItem("tls_services", item)
				}
				if s.TLS {
					proof.TLS++
				}
			}
		}
		for _, e := range surface.Endpoints {
			key := surface.Scope + ":" + e.ID
			item := ProofItem{ID: key, EndpointID: e.ID, Scope: surface.Scope, URL: SafeTelemetryURL(e.URL), Method: e.Method, State: e.State, Reason: e.StateReason}
			lookup[key] = item
			addItem("discovered", item)
			if e.ObservationKind == "observed" {
				proof.Observed++
				addItem("observed", item)
			}
			if e.State == "" || e.State == EndpointStateInScope {
				proof.Approved++
				addItem("approved", item)
				for _, scanner := range []string{"zap", "nuclei", "wapiti", "dalfox"} {
					if ok, _ := endpointEligibleWithPolicy(e, scanner, nil, expanded); ok {
						proof.Eligible++
						addItem("eligible", item)
						break
					}
				}
			}
			if e.ObservationKind == "seed" {
				proof.Seeds++
				addItem("seeds", item)
			}
			if e.HasForm {
				proof.Forms++
				addItem("forms", item)
			}
			if e.HasParameters {
				proof.Parameterized++
				addItem("parameterized", item)
			}
			if e.ObservedWithAuth {
				proof.ObservedWithAuth++
				addItem("observed_with_auth", item)
			}
			for _, c := range e.ScannerCoverage {
				state := get(c.Scanner)
				key := surface.Scope + ":" + e.ID
				item := lookup[key]
				item.AttemptID, item.Reason, item.State, item.EvidenceRef = c.AttemptID, c.Reason, c.Status, c.EvidenceRef
				scannerLookup[c.Scanner+"\x00"+key] = item
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
	latest := map[string]int{}
	for i, run := range runs {
		key := run.Scanner + "\x00" + run.Scope
		if old, ok := latest[key]; ok {
			oldTime, _ := time.Parse(time.RFC3339Nano, runs[old].StartedAt)
			newTime, _ := time.Parse(time.RFC3339Nano, run.StartedAt)
			if oldTime.After(newTime) {
				continue
			}
		}
		latest[key] = i
	}
	for i, run := range runs {
		if latest[run.Scanner+"\x00"+run.Scope] != i {
			continue
		}
		state := get(run.Scanner)
		inventoryScopes := map[string]string{}
		if data, err := os.ReadFile(run.TemplateInventoryPath); err == nil {
			var inventory TemplateInventory
			if json.Unmarshal(data, &inventory) == nil && inventory.State == "enabled" {
				n := len(inventory.Templates)
				state.enabled = &n
				for _, template := range inventory.Templates {
					addItem(run.Scanner+":enabled_templates", ProofItem{ID: template, URL: template, State: "enabled", Reason: "Template enabled by policy; executed checks NOT TRACKED", AttemptID: run.AttemptID, EvidenceRef: run.TemplateInventoryPath})
				}
			}
		}
		data, err := os.ReadFile(run.InputManifestPath)
		if err == nil {
			var manifest ScannerInputManifest
			if json.Unmarshal(data, &manifest) == nil {
				for _, r := range manifest.Requests {
					scope := r.InventoryScope
					if scope == "" {
						scope = run.Scope
					}
					inventoryScopes[r.EndpointID] = scope
					key := scope + ":" + r.EndpointID
					item := lookup[key]
					if item.ID == "" {
						item = ProofItem{ID: key, EndpointID: r.EndpointID, Scope: run.Scope, URL: r.URL, Method: r.Method}
					}
					item.AttemptID, item.Reason = run.AttemptID, r.Reason
					scannerLookup[run.Scanner+"\x00"+key] = item
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
			scope := inventoryScopes[s.EndpointID]
			if scope == "" {
				scope = run.Scope
			}
			key := scope + ":" + s.EndpointID
			item := scannerLookup[run.Scanner+"\x00"+key]
			if item.ID == "" {
				item = lookup[key]
			}
			item.AttemptID, item.State, item.Reason, item.EvidenceRef = run.AttemptID, s.Status, s.Reason, s.EvidenceRef
			scannerLookup[run.Scanner+"\x00"+key] = item
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
					scope := inventoryScopes[id]
					if scope == "" {
						scope = run.Scope
					}
					key := scope + ":" + id
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
		row := ScannerProof{EnabledTemplates: state.enabled, Scanner: name, Selected: len(state.selected), Submitted: len(state.submitted), Acknowledged: len(state.ack), BatchCompleted: len(state.batch), Failed: len(state.failed), Skipped: len(state.skipped), Unknown: len(state.selected)}
		if state.recorded {
			n := len(state.exercised)
			row.Exercised = &n
			row.Unknown -= n
			if row.Unknown < 0 {
				row.Unknown = 0
			}
		}
		for metric, entries := range map[string]map[string]bool{"selected": state.selected, "submitted": state.submitted, "acknowledged": state.ack, "exercised": state.exercised, "batch_completed": state.batch, "failed": state.failed, "skipped": state.skipped} {
			keys := make([]string, 0, len(entries))
			for key := range entries {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				item := scannerLookup[name+"\x00"+key]
				if item.ID == "" {
					item = lookup[key]
				}
				if item.ID == "" {
					item.ID = key
				}
				addItem(name+":"+metric, item)
			}
		}
		for key := range state.selected {
			if !state.exercised[key] {
				item := scannerLookup[name+"\x00"+key]
				if item.ID == "" {
					item = lookup[key]
				}
				if item.ID == "" {
					item.ID = key
				}
				addItem(name+":unknown", item)
			}
		}
		proof.Scanners = append(proof.Scanners, row)
	}
	for _, items := range proof.Items {
		sort.SliceStable(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	}
	return proof
}

package scanner

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Finding is the private, deterministic report-input record. It is not a
// scan-time UI finding and is only consumed after all scanner attempts finish.
type Finding struct {
	SourceID    string  `json:"source_id"`
	Scanner     string  `json:"scanner"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	Target      string  `json:"target,omitempty"`
	Endpoint    string  `json:"endpoint,omitempty"`
	Description string  `json:"description,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
	EvidenceRef string  `json:"evidence_reference"`
	CVE         string  `json:"cve,omitempty"`
	CWE         string  `json:"cwe,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	// Scope is the (scope) key of the run that produced this finding, e.g.
	// "host:api.example.com" or "source:main", so the report can group by it.
	Scope string `json:"scope,omitempty"`
	// Sources is set only when cross-scanner merge collapsed several scanners'
	// reports of one CVE on one scope into this finding; it lists every
	// contributor, this finding's own report first.
	Sources []FindingSource `json:"sources,omitempty"`
}

func ParseRuns(runs []Run) ([]Finding, []error) {
	var findings []Finding
	var errs []error
	for _, run := range runs {
		if run.Status != "completed" || run.ArtifactPath == "" {
			continue
		}
		parsed, err := ParseRun(run)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", run.Scanner, err))
		}
		scope := FindingScope(run)
		for i := range parsed {
			parsed[i].EvidenceRef = run.ArtifactPath + "#" + parsed[i].SourceID
			parsed[i].Scope = scope
		}
		findings = append(findings, parsed...)
	}
	findings = mergeCrossScanner(dedupFindings(findings))
	return findings, errs
}

// FindingScope is the report scope a run's findings belong to: its own scope,
// a pre-scope run folded to the implicit host scope, or — for a per-host nmap
// recon run ("recon:<target>:<host>") — that host's scope.
func FindingScope(run Run) string {
	if run.Scope == "" {
		// A pre-scope (Increment-1) run folds to the implicit host scope, the
		// same rule indexTerminal applies on resume.
		return HostScope(run.Target).Key()
	}
	// Strip the known "recon:<target>:" prefix rather than splitting on the last
	// ":" — targets such as "localhost:3000" contain colons themselves.
	if prefix := reconScopeKey(run.Target) + ":"; strings.HasPrefix(run.Scope, prefix) {
		return HostScope(strings.TrimPrefix(run.Scope, prefix)).Key()
	}
	return run.Scope
}

func ParseRun(run Run) ([]Finding, error) {
	switch run.Scanner {
	case "nuclei":
		return parseNuclei(run.ArtifactPath)
	case "zap":
		return parseZAP(run.ArtifactPath)
	case "openvas":
		return parseOpenVAS(run.ArtifactPath)
	case "trivy":
		return parseTrivy(run.ArtifactPath)
	case "semgrep":
		return parseSemgrep(run.ArtifactPath)
	case "gitleaks":
		return parseGitleaks(run.ArtifactPath)
	case "osv":
		return parseOSV(run.ArtifactPath)
	case "vuls":
		return parseVuls(run.ArtifactPath)
	case "nmap":
		return parseNmap(run.ArtifactPath)
	case "testssl":
		return parseTestssl(run.ArtifactPath)
	case "subfinder", "httpx":
		return nil, nil // recon evidence tools produce no findings
	default:
		return nil, fmt.Errorf("unsupported scanner %q", run.Scanner)
	}
}

func parseNuclei(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Finding
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 8<<20)
	line := 0
	for s.Scan() {
		line++
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal(s.Bytes(), &v); err != nil {
			return out, fmt.Errorf("line %d: %w", line, err)
		}
		info, _ := v["info"].(map[string]any)
		id := str(v["template-id"])
		if id == "" {
			id = fmt.Sprintf("line-%d", line)
		}
		out = append(out, Finding{SourceID: "nuclei:" + id + ":" + str(v["matched-at"]), Scanner: "nuclei", Title: firstNonEmpty(str(info["name"]), id), Severity: severity(str(info["severity"])), Target: str(v["host"]), Endpoint: str(v["matched-at"]), Description: str(info["description"]), Evidence: firstNonEmpty(str(v["matcher-name"]), str(v["extracted-results"])), CVE: firstString(info["classification"], "cve-id"), CWE: firstString(info["classification"], "cwe-id"), CVSS: firstFloat(info["classification"], "cvss-score")})
	}
	return out, s.Err()
}

func parseZAP(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	alerts := array(root["alerts"])
	if len(alerts) == 0 {
		for _, site := range array(root["site"]) {
			m, _ := site.(map[string]any)
			alerts = append(alerts, array(m["alerts"])...)
		}
	}
	out := make([]Finding, 0, len(alerts))
	for i, a := range alerts {
		m, _ := a.(map[string]any)
		instances := array(m["instances"])
		// Grouped report alerts carry their URLs in instances; the alerts view
		// returns one record per URL instead.
		endpoint := str(m["url"])
		evidence := str(m["evidence"])
		if len(instances) > 0 {
			im, _ := instances[0].(map[string]any)
			endpoint = firstNonEmpty(str(im["uri"]), endpoint)
			if evidence == "" {
				evidence = str(im["evidence"])
			}
		}
		id := firstNonEmpty(str(m["pluginId"]), str(m["pluginid"]), strconv.Itoa(i))
		out = append(out, Finding{SourceID: "zap:" + id + ":" + endpoint, Scanner: "zap", Title: firstNonEmpty(str(m["name"]), str(m["alert"]), id), Severity: zapSeverity(firstNonEmpty(str(m["riskdesc"]), str(m["risk"]), str(m["riskcode"]))), Endpoint: endpoint, Description: firstNonEmpty(str(m["desc"]), str(m["description"])), Evidence: evidence, CWE: str(m["cweid"])})
	}
	return out, nil
}

func parseTrivy(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	var out []Finding
	for _, rv := range array(root["Results"]) {
		r, _ := rv.(map[string]any)
		target := str(r["Target"])
		for _, key := range []string{"Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"} {
			for i, item := range array(r[key]) {
				m, _ := item.(map[string]any)
				id := firstNonEmpty(str(m["VulnerabilityID"]), str(m["ID"]), str(m["RuleID"]), fmt.Sprintf("%s-%d", key, i))
				out = append(out, Finding{SourceID: "trivy:" + id + ":" + target, Scanner: "trivy", Title: firstNonEmpty(str(m["Title"]), str(m["PkgName"]), id), Severity: severity(str(m["Severity"])), Target: target, Endpoint: firstNonEmpty(str(m["PkgPath"]), str(m["Target"])), Description: firstNonEmpty(str(m["Description"]), str(m["Message"])), Evidence: firstNonEmpty(str(m["InstalledVersion"]), str(m["CauseMetadata"])), CVE: asCVE(id), CVSS: maxCVSS(m["CVSS"])})
			}
		}
	}
	return out, nil
}

func parseOpenVAS(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type result struct {
		ID          string `xml:"id,attr"`
		Name        string `xml:"name"`
		Host        string `xml:"host"`
		Port        string `xml:"port"`
		Threat      string `xml:"threat"`
		Severity    string `xml:"severity"`
		Description string `xml:"description"`
		NVT         struct {
			OID  string `xml:"oid,attr"`
			CVE  string `xml:"cve"`
			CVSS string `xml:"cvss_base"`
		} `xml:"nvt"`
	}
	var doc struct {
		Results []result `xml:"report>results>result"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Results) == 0 {
		var alt struct {
			Results []result `xml:"results>result"`
		}
		_ = xml.Unmarshal(data, &alt)
		doc.Results = alt.Results
	}
	out := make([]Finding, 0, len(doc.Results))
	for _, r := range doc.Results {
		score, _ := strconv.ParseFloat(strings.TrimSpace(r.Severity), 64)
		out = append(out, Finding{SourceID: "openvas:" + firstNonEmpty(r.ID, r.NVT.OID), Scanner: "openvas", Title: r.Name, Severity: cvssSeverity(score, r.Threat), Target: r.Host, Endpoint: r.Port, Description: r.Description, Evidence: "Greenbone NVT " + r.NVT.OID, CVE: firstCSV(r.NVT.CVE), CVSS: score})
	}
	return out, nil
}

// parseSemgrep reads semgrep --json output. SourceID is semgrep:rule:file:line.
func parseSemgrep(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	var out []Finding
	for _, rv := range array(root["results"]) {
		r, _ := rv.(map[string]any)
		rule := str(r["check_id"])
		file := str(r["path"])
		start, _ := r["start"].(map[string]any)
		line := str(start["line"])
		extra, _ := r["extra"].(map[string]any)
		out = append(out, Finding{
			SourceID:    "semgrep:" + rule + ":" + file + ":" + line,
			Scanner:     "semgrep",
			Title:       firstNonEmpty(rule, "semgrep finding"),
			Severity:    semgrepSeverity(str(extra["severity"])),
			Target:      file,
			Endpoint:    file + ":" + line,
			Description: str(extra["message"]),
		})
	}
	return out, nil
}

// semgrepSeverity maps semgrep's ERROR/WARNING/INFO to the shared scale.
func semgrepSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	default:
		return "low"
	}
}

// parseGitleaks reads gitleaks' JSON array. Secrets have no native severity;
// they are reported high. SourceID is gitleaks:rule:file:commit.
func parseGitleaks(path string) ([]Finding, error) {
	var entries []map[string]any
	if err := readJSON(path, &entries); err != nil {
		return nil, err
	}
	var out []Finding
	for _, m := range entries {
		rule := str(m["RuleID"])
		file := str(m["File"])
		commit := str(m["Commit"])
		out = append(out, Finding{
			SourceID:    "gitleaks:" + rule + ":" + file + ":" + commit,
			Scanner:     "gitleaks",
			Title:       firstNonEmpty(rule, "secret"),
			Severity:    "high",
			Target:      file,
			Endpoint:    file + ":" + str(m["StartLine"]),
			Description: firstNonEmpty(str(m["Description"]), "secret detected"),
		})
	}
	return out, nil
}

// parseOSV reads osv-scanner --format json. SourceID is osv:pkg:vulnID; the CVE
// is taken from the first CVE alias when present.
func parseOSV(path string) ([]Finding, error) {
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	var out []Finding
	for _, rv := range array(root["results"]) {
		r, _ := rv.(map[string]any)
		src, _ := r["source"].(map[string]any)
		srcPath := str(src["path"])
		for _, pv := range array(r["packages"]) {
			pkgObj, _ := pv.(map[string]any)
			pkg, _ := pkgObj["package"].(map[string]any)
			name := str(pkg["name"])
			for _, vv := range array(pkgObj["vulnerabilities"]) {
				v, _ := vv.(map[string]any)
				id := str(v["id"])
				cve := ""
				for _, a := range array(v["aliases"]) {
					if c := asCVE(str(a)); c != "" {
						cve = c
						break
					}
				}
				out = append(out, Finding{
					SourceID:    "osv:" + name + ":" + id,
					Scanner:     "osv",
					Title:       firstNonEmpty(id, name),
					Severity:    "medium",
					Target:      name,
					Endpoint:    srcPath,
					Description: str(v["summary"]),
					CVE:         cve,
				})
			}
		}
	}
	return out, nil
}

func parseVuls(path string) ([]Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		var candidates []string
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
			if e == nil && !d.IsDir() && strings.HasSuffix(strings.ToLower(p), ".json") {
				candidates = append(candidates, p)
			}
			return nil
		})
		sort.Strings(candidates)
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no Vuls JSON report found")
		}
		path = candidates[len(candidates)-1]
	}
	var root map[string]any
	if err := readJSON(path, &root); err != nil {
		return nil, err
	}
	server := firstNonEmpty(str(root["serverName"]), str(root["ServerName"]))
	cves := object(root["scannedCves"])
	if len(cves) == 0 {
		cves = object(root["ScannedCves"])
	}
	var out []Finding
	for id, val := range cves {
		m, _ := val.(map[string]any)
		score := firstFloat(m, "cvss3Score")
		out = append(out, Finding{SourceID: "vuls:" + id + ":" + server, Scanner: "vuls", Title: firstNonEmpty(str(m["title"]), id), Severity: cvssSeverity(score, ""), Target: server, Description: str(m["summary"]), Evidence: firstNonEmpty(str(m["affectedPackages"]), str(m["cveContents"])), CVE: asCVE(id), CVSS: score})
	}
	return out, nil
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Addresses []nmapAddr `xml:"address"`
	Ports     []nmapPort `xml:"ports>port"`
}
type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}
type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   string    `xml:"portid,attr"`
	State    nmapState `xml:"state"`
	Service  nmapSvc   `xml:"service"`
}
type nmapState struct {
	State string `xml:"state,attr"`
}
type nmapSvc struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func parseNmap(path string) ([]Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(b, &run); err != nil {
		return nil, err
	}
	var out []Finding
	for _, h := range run.Hosts {
		host := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				host = a.Addr
				break
			}
		}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			out = append(out, Finding{
				SourceID: "nmap:" + host + ":" + p.PortID,
				Scanner:  "nmap",
				Title:    firstNonEmpty(p.Service.Name, "open port "+p.PortID),
				Severity: "info",
				Target:   host,
				Endpoint: p.PortID,
				Evidence: strings.TrimSpace(p.Service.Product + " " + p.Service.Version),
			})
		}
	}
	return out, nil
}

// parseTestssl reads testssl.sh's flat --jsonfile array and emits one Finding
// per actionable entry (severity LOW and above). OK/INFO/DEBUG/WARN entries are
// status lines, not vulnerabilities, and are dropped so the report stays focused.
func parseTestssl(path string) ([]Finding, error) {
	var entries []map[string]any
	if err := readJSON(path, &entries); err != nil {
		return nil, err
	}
	actionable := map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	var out []Finding
	for _, m := range entries {
		sev := strings.ToUpper(strings.TrimSpace(str(m["severity"])))
		if !actionable[sev] {
			continue
		}
		id := str(m["id"])
		host := str(m["ip"])
		if i := strings.IndexByte(host, '/'); i >= 0 { // "fqdn/ip" -> "fqdn"
			host = host[:i]
		}
		port := str(m["port"])
		// testssl can list several space-separated CVEs in one entry
		// (e.g. "CVE-2016-2183 CVE-2016-6329"); keep the first, matching the
		// single-CVE convention the other parsers use via firstCSV.
		cve := str(m["cve"])
		if fields := strings.Fields(cve); len(fields) > 0 {
			cve = fields[0]
		}
		out = append(out, Finding{
			SourceID:    "testssl:" + host + ":" + port + ":" + id,
			Scanner:     "testssl",
			Title:       firstNonEmpty(id, "TLS finding"),
			Severity:    severity(sev),
			Target:      host,
			Endpoint:    host + ":" + port,
			Description: str(m["finding"]),
			CVE:         asCVE(firstCSV(cve)),
			CWE:         str(m["cwe"]),
		})
	}
	return out, nil
}

// dedupFindings drops exact repeats within one scope. Scope is part of the key:
// nmap SourceIDs use the resolved IP, so two host scopes on one IP would
// otherwise collapse into one finding and lose a host's report.
func dedupFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		k := strings.ToLower(strings.Join([]string{f.Scope, f.Scanner, f.SourceID, f.Target, f.Endpoint}, "|"))
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
func str(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []any:
		var s []string
		for _, v := range x {
			s = append(s, str(v))
		}
		return strings.Join(s, ", ")
	case map[string]any:
		b, _ := json.Marshal(x)
		return string(b)
	default:
		return ""
	}
}
func array(v any) []any           { x, _ := v.([]any); return x }
func object(v any) map[string]any { x, _ := v.(map[string]any); return x }
func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
func severity(s string) string {
	s = strings.ToLower(s)
	for _, v := range []string{"critical", "high", "medium", "low", "info"} {
		if strings.Contains(s, v) {
			return v
		}
	}
	return "info"
}
func zapSeverity(s string) string {
	switch severity(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	switch strings.TrimSpace(s) {
	case "3", "4":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	}
	return "info"
}
func cvssSeverity(score float64, fallback string) string {
	if score >= 9 {
		return "critical"
	}
	if score >= 7 {
		return "high"
	}
	if score >= 4 {
		return "medium"
	}
	if score > 0 {
		return "low"
	}
	return severity(fallback)
}
func firstString(v any, key string) string { m, _ := v.(map[string]any); return firstCSV(str(m[key])) }
func firstFloat(v any, key string) float64 {
	m, _ := v.(map[string]any)
	if n, ok := m[key].(float64); ok {
		return n
	}
	n, _ := strconv.ParseFloat(str(m[key]), 64)
	return n
}
func firstCSV(s string) string {
	if i := strings.Index(s, ","); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
func asCVE(s string) string {
	if strings.HasPrefix(strings.ToUpper(s), "CVE-") {
		return strings.ToUpper(s)
	}
	return ""
}
func maxCVSS(v any) float64 {
	m, _ := v.(map[string]any)
	max := 0.0
	for _, x := range m {
		sm, _ := x.(map[string]any)
		for _, k := range []string{"V3Score", "V2Score"} {
			n, _ := strconv.ParseFloat(str(sm[k]), 64)
			if n > max {
				max = n
			}
		}
	}
	return max
}

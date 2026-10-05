package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Finding is the private, deterministic report-input record. It is not a
// scan-time UI finding and is only consumed after all scanner attempts finish.
type Finding struct {
	SourceID          string  `json:"source_id"`
	Scanner           string  `json:"scanner"`
	RuleID            string  `json:"rule_id,omitempty"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	Target            string  `json:"target,omitempty"`
	Endpoint          string  `json:"endpoint,omitempty"`
	Method            string  `json:"method,omitempty"`
	Parameter         string  `json:"parameter,omitempty"`
	ParameterLocation string  `json:"parameter_location,omitempty"`
	Protocol          string  `json:"protocol,omitempty"`
	Port              string  `json:"port,omitempty"`
	Package           string  `json:"package,omitempty"`
	PackageVersion    string  `json:"package_version,omitempty"`
	SourceLocation    string  `json:"source_location,omitempty"`
	Container         string  `json:"container,omitempty"`
	Resource          string  `json:"resource,omitempty"`
	Description       string  `json:"description,omitempty"`
	Evidence          string  `json:"evidence,omitempty"`
	NativeMessageID   string  `json:"native_message_id,omitempty"`
	Attack            string  `json:"attack,omitempty"`
	Remediation       string  `json:"remediation,omitempty"`
	EvidenceRef       string  `json:"evidence_reference"`
	CVE               string  `json:"cve,omitempty"`
	CWE               string  `json:"cwe,omitempty"`
	CVSS              float64 `json:"cvss,omitempty"`
	// SeverityUnrated marks a placeholder severity: the scanner gave no rating
	// (e.g. an OSV entry with no CVSS or database severity). Merge and the AI
	// severity floor ignore it rather than treat the placeholder as a rating.
	SeverityUnrated bool `json:"severity_unrated,omitempty"`
	// Scope is the (scope) key of the run that produced this finding, e.g.
	// "host:api.example.com" or "source:main", so the report can group by it.
	Scope string `json:"scope,omitempty"`
	// Sources is set only when cross-scanner merge collapsed several scanners'
	// reports of one CVE on one scope into this finding; it lists every
	// contributor, this finding's own report first.
	Sources              []FindingSource `json:"sources,omitempty"`
	Fingerprint          string          `json:"fingerprint,omitempty"`
	Confidence           string          `json:"confidence,omitempty"`
	NativeConfidence     string          `json:"native_confidence,omitempty"`
	EvidenceCompleteness string          `json:"evidence_completeness,omitempty"`
}

func FindingFingerprint(f Finding) string {
	identity := strings.ToUpper(strings.TrimSpace(f.CVE))
	if identity == "" {
		identity = strings.ToUpper(strings.TrimSpace(f.CWE))
	}
	if identity == "" {
		// Without a vulnerability identifier, the native record key is the most
		// stable available identity. Titles and severity are presentation data.
		identity = strings.ToLower(f.Scanner) + ":" + f.SourceID
	}
	target := f.Target
	if strings.HasPrefix(f.Scope, "source:") {
		target = filepath.ToSlash(filepath.Clean(target))
	}
	key := strings.Join([]string{identity, f.Scope, target, f.Endpoint, strings.ToUpper(strings.TrimSpace(f.Method)), strings.TrimSpace(f.Parameter)}, "\x00")
	return fmt.Sprintf("v2:%x", sha256.Sum256([]byte(key)))
}

func ParseRuns(runs []Run) ([]Finding, []error) {
	var findings []Finding
	var errs []error
	for _, run := range runs {
		budgetPartial := run.Status == "failed" && (run.Scanner == "nikto" || run.Scanner == "nuclei") &&
			(strings.Contains(run.Reason, "time budget reached") || strings.Contains(run.Reason, "time budget exhausted"))
		partialTestssl := run.Scanner == "testssl" && run.Status == "failed"
		if (run.Status != "completed" && !budgetPartial && !partialTestssl) || run.ArtifactPath == "" {
			continue
		}
		if partialTestssl {
			if _, statErr := os.Stat(run.ArtifactPath); statErr != nil {
				continue
			}
			if err := VerifyChecksum(run); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		parsed, err := ParseRun(run)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", run.Scanner, err))
		}
		scope := FindingScope(run)
		// Source-scope paths become relative to the checkout (run.Target). The
		// SourceID and EvidenceRef keep the native path: they are trace keys.
		sourceRoot := ""
		if strings.HasPrefix(scope, "source:") {
			sourceRoot = run.Target
		}
		for i := range parsed {
			parsed[i].EvidenceRef = run.ArtifactPath + "#" + parsed[i].SourceID
			parsed[i].Scope = scope
			if parsed[i].EvidenceCompleteness == "" {
				parsed[i].EvidenceCompleteness = "artifact"
			}
			if partialTestssl {
				parsed[i].EvidenceCompleteness = "partial"
			}
			if sourceRoot != "" {
				parsed[i].Target = relativeToRoot(parsed[i].Target, sourceRoot)
				parsed[i].Endpoint = relativeToRoot(parsed[i].Endpoint, sourceRoot)
			}
			parsed[i].Fingerprint = FindingFingerprint(parsed[i])
		}
		findings = append(findings, parsed...)
	}
	findings = mergeCrossScanner(dedupFindings(findings))
	return findings, errs
}

// relativeToRoot rewrites a finding path under root (the source checkout) to be
// relative to it, so finding Target/Endpoint never show the internal checkout
// path (SourceIDs and evidence references keep native paths by design: they
// are trace keys) and scanners that report absolute vs relative paths agree.
// Paths outside root, and any path when root is empty, are returned unchanged.
// p may carry a ":line" suffix.
func relativeToRoot(p, root string) string {
	root = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(root)), "/")
	if root == "" || root == "." {
		return p
	}
	if rest, ok := strings.CutPrefix(filepath.ToSlash(p), root+"/"); ok {
		return rest
	}
	return p
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
	case "apichecks":
		return parseAPIChecks(run.ArtifactPath)
	case "apiwrites":
		// The write adapter artifact records operation and cleanup status, not
		// scanner findings. Findings are reported only by verification adapters.
		return nil, nil
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
	case "lynis":
		return parseLynis(run.ArtifactPath)
	case "nmap":
		return parseNmap(run.ArtifactPath)
	case "testssl":
		return parseTestssl(run.ArtifactPath)
	case "sslyze":
		return parseSSLyze(run.ArtifactPath)
	case "masscan", "subfinder", "amass", "dnsx", "gau", "waybackurls", "httpx", "katana", "auth":
		return nil, nil // recon/discovery evidence tools produce no findings
	case "nikto":
		return parseNikto(run.ArtifactPath)
	case "dalfox":
		return parseDalfox(run.ArtifactPath)
	case "wapiti":
		return parseWapiti(run.ArtifactPath)
	case "kube-bench":
		return parseKubeBench(run.ArtifactPath)
	case "prowler":
		return parseProwler(run.ArtifactPath)
	case "scoutsuite":
		return parseScoutSuite(run.ArtifactPath)
	default:
		return nil, fmt.Errorf("unsupported scanner %q", run.Scanner)
	}
}

var niktoCVEPattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

func normalizeScannerConfidence(scanner, raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch scanner {
	case "zap":
		switch {
		case strings.Contains(value, "high"), value == "3":
			return "HIGH"
		case strings.Contains(value, "medium"), value == "2":
			return "MEDIUM"
		case strings.Contains(value, "low"), value == "1":
			return "LOW"
		}
	}
	return ""
}

func parseNikto(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode Nikto JSON: %w", err)
	}
	var hosts []any
	switch value := root.(type) {
	case []any:
		hosts = value
	case map[string]any:
		hosts = []any{value}
	default:
		return nil, fmt.Errorf("Nikto JSON must be an object or array")
	}
	var out []Finding
	for _, rawHost := range hosts {
		host := object(rawHost)
		if host == nil {
			continue
		}
		vulnerabilities := array(host["vulnerabilities"])
		if len(vulnerabilities) == 0 && (host["msg"] != nil || host["message"] != nil) {
			vulnerabilities = []any{host}
		}
		for index, rawIssue := range vulnerabilities {
			issue := object(rawIssue)
			if issue == nil {
				continue
			}
			message := firstNonEmpty(str(issue["msg"]), str(issue["message"]))
			if message == "" {
				continue
			}
			uri := firstNonEmpty(str(issue["url"]), str(issue["uri"]))
			endpoint := niktoEndpoint(host, uri)
			method := strings.ToUpper(firstNonEmpty(str(issue["method"]), "GET"))
			id := firstNonEmpty(str(issue["id"]), str(issue["testid"]), strconv.Itoa(index+1))
			refs := firstNonEmpty(str(issue["refs"]), str(issue["references"]))
			cve := ""
			if match := niktoCVEPattern.FindString(refs + " " + message); match != "" {
				cve = strings.ToUpper(match)
			}
			evidence := "Nikto test " + id + " (" + method + ")"
			if refs != "" {
				evidence += "; references: " + refs
			}
			out = append(out, Finding{
				SourceID: "nikto:" + str(host["host"]) + ":" + str(host["port"]) + ":" + id + ":" + method + ":" + uri,
				Scanner:  "nikto", Title: message, Severity: "info", SeverityUnrated: true,
				RuleID: id,
				Target: firstNonEmpty(str(host["host"]), str(host["ip"])), Endpoint: endpoint,
				Description: message, Evidence: evidence, CVE: cve,
			})
		}
	}
	return out, nil
}

func niktoEndpoint(host map[string]any, uri string) string {
	if uri == "" {
		return ""
	}
	if parsed, err := url.Parse(uri); err == nil && parsed.IsAbs() {
		return parsed.String()
	}
	name := firstNonEmpty(str(host["host"]), str(host["ip"]))
	if name == "" {
		return uri
	}
	port := str(host["port"])
	scheme := "http"
	if niktoTLS(host["ssl"]) || niktoTLS(host["tls"]) {
		scheme = "https"
	}
	if port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		name = net.JoinHostPort(name, port)
	}
	if strings.HasPrefix(uri, "/") {
		return scheme + "://" + name + uri
	}
	return scheme + "://" + name + "/" + uri
}

func niktoTLS(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case float64:
		return v == 1
	case string:
		return strings.EqualFold(v, "true") || v == "1"
	default:
		return false
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
		out = append(out, Finding{SourceID: "nuclei:" + id + ":" + str(v["matched-at"]), Scanner: "nuclei", RuleID: id, Title: firstNonEmpty(str(info["name"]), id), Severity: severity(str(info["severity"])), Target: str(v["host"]), Endpoint: str(v["matched-at"]), Description: str(info["description"]), Evidence: firstNonEmpty(str(v["matcher-name"]), str(v["extracted-results"])), CVE: firstString(info["classification"], "cve-id"), CWE: firstString(info["classification"], "cwe-id"), CVSS: firstFloat(info["classification"], "cvss-score")})
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
		if len(instances) == 0 {
			instances = []any{nil}
		}
		for j, instance := range instances {
			im, _ := instance.(map[string]any)
			if im == nil {
				im = m
			}
			// Grouped report alerts carry their URLs in instances; the alerts view
			// returns one record per URL instead.
			endpoint := str(m["url"])
			evidence := str(m["evidence"])
			if instance != nil {
				endpoint = firstNonEmpty(str(im["uri"]), endpoint)
				if evidence == "" {
					evidence = str(im["evidence"])
				}
			}
			id := firstNonEmpty(str(m["pluginId"]), str(m["pluginid"]), strconv.Itoa(i))
			nativeConfidence := firstNonEmpty(str(m["confidence"]), str(m["confidencecode"]))
			out = append(out, Finding{SourceID: fmt.Sprintf("zap:%s:%d:%s", id, j, endpoint), Scanner: "zap", RuleID: id, Title: firstNonEmpty(str(m["name"]), str(m["alert"]), id), Severity: zapSeverity(firstNonEmpty(str(m["riskdesc"]), str(m["risk"]), str(m["riskcode"]))), Endpoint: endpoint, Method: str(im["method"]), Parameter: str(im["param"]), NativeMessageID: str(m["messageId"]), Attack: str(m["attack"]), Description: firstNonEmpty(str(m["desc"]), str(m["description"])), Evidence: evidence, Remediation: firstNonEmpty(str(m["solution"]), str(m["remediation"])), CWE: str(m["cweid"]), Confidence: normalizeScannerConfidence("zap", nativeConfidence), NativeConfidence: nativeConfidence})
		}
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
				out = append(out, Finding{SourceID: "trivy:" + id + ":" + target, Scanner: "trivy", RuleID: id, Title: firstNonEmpty(str(m["Title"]), str(m["PkgName"]), id), Severity: severity(str(m["Severity"])), Target: target, Endpoint: firstNonEmpty(str(m["PkgPath"]), str(m["Target"])), Package: str(m["PkgName"]), PackageVersion: str(m["InstalledVersion"]), Description: firstNonEmpty(str(m["Description"]), str(m["Message"])), Evidence: firstNonEmpty(str(m["InstalledVersion"]), str(m["CauseMetadata"])), CVE: asCVE(id), CVSS: maxCVSS(m["CVSS"])})
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
	// gvmd's get_reports nests the result-bearing <report> inside an outer
	// <report> (get_reports_response > report > report > results > result).
	// The flatter shapes are accepted for older exports and fixtures.
	var doc struct {
		Nested []result `xml:"report>report>results>result"`
		Flat   []result `xml:"report>results>result"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	results := doc.Nested
	if len(results) == 0 {
		results = doc.Flat
	}
	if len(results) == 0 {
		var alt struct {
			Results []result `xml:"results>result"`
		}
		_ = xml.Unmarshal(data, &alt)
		results = alt.Results
	}
	out := make([]Finding, 0, len(results))
	for _, r := range results {
		score, _ := strconv.ParseFloat(strings.TrimSpace(r.Severity), 64)
		// "Log" results are detection notes (open ports, OS and service
		// identification), not vulnerabilities; Greenbone's default view hides them.
		if strings.EqualFold(strings.TrimSpace(r.Threat), "log") && score <= 0 {
			continue
		}
		host := strings.TrimSpace(r.Host)
		out = append(out, Finding{SourceID: "openvas:" + firstNonEmpty(r.ID, r.NVT.OID), Scanner: "openvas", RuleID: r.NVT.OID, Title: strings.TrimSpace(r.Name), Severity: cvssSeverity(score, r.Threat), Target: host, Endpoint: r.Port, Port: r.Port, Description: r.Description, Evidence: "Greenbone NVT " + r.NVT.OID, CVE: firstCSV(r.NVT.CVE), CVSS: score})
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
			RuleID:      rule,
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
			RuleID:      rule,
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
				sev, cvss, rated := osvSeverity(pkgObj, v, id)
				out = append(out, Finding{
					SourceID:        "osv:" + name + ":" + id,
					Scanner:         "osv",
					RuleID:          id,
					Title:           firstNonEmpty(id, name),
					Severity:        sev,
					SeverityUnrated: !rated,
					CVSS:            cvss,
					Target:          srcPath,
					Endpoint:        srcPath,
					Description:     str(v["summary"]),
					Evidence:        osvPackageLabel(pkg),
					CVE:             cve,
				})
			}
		}
	}
	return out, nil
}

// osvSeverity rates one OSV vulnerability. osv-scanner reports a numeric CVSS
// max_severity per alias group; GHSA records also carry a textual
// database_specific.severity. With neither, the finding is an unrated "medium"
// placeholder.
func osvSeverity(pkgObj map[string]any, v map[string]any, id string) (string, float64, bool) {
	for _, gv := range array(pkgObj["groups"]) {
		g, _ := gv.(map[string]any)
		for _, gid := range array(g["ids"]) {
			if str(gid) != id {
				continue
			}
			if score, err := strconv.ParseFloat(str(g["max_severity"]), 64); err == nil && score > 0 {
				return cvssSeverity(score, ""), score, true
			}
		}
	}
	db, _ := v["database_specific"].(map[string]any)
	switch strings.ToLower(str(db["severity"])) {
	case "critical":
		return "critical", 0, true
	case "high":
		return "high", 0, true
	case "moderate", "medium":
		return "medium", 0, true
	case "low":
		return "low", 0, true
	}
	return "medium", 0, false
}

func osvPackageLabel(pkg map[string]any) string {
	name, version := str(pkg["name"]), str(pkg["version"])
	if version == "" {
		return name
	}
	return name + "@" + version
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
	Tunnel  string `xml:"tunnel,attr"`
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
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	start, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if start != json.Delim('[') {
		return nil, fmt.Errorf("testssl results must be a JSON array")
	}
	actionable := map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	var out []Finding
	for decoder.More() {
		var m map[string]any
		if err := decoder.Decode(&m); err != nil {
			return out, fmt.Errorf("testssl JSON stopped after %d complete findings: %w", len(out), err)
		}
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
	end, err := decoder.Token()
	if err != nil {
		return out, fmt.Errorf("testssl JSON ended before array closed: %w", err)
	}
	if end != json.Delim(']') {
		return out, fmt.Errorf("testssl JSON array has invalid terminator")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return out, fmt.Errorf("testssl JSON has trailing data")
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

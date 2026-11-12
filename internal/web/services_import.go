package web

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// Services import turns a CSV or YAML list of microservices into rows for
// the New Scan services table. It only parses and validates; nothing is
// scanned or stored. CSV header: name,url,image,repo[,protected_path] where
// url may hold several URLs separated by ";".

const (
	maxServicesImportBytes = 1 << 20
	maxImportedServices    = 500
)

type importedService struct {
	Name          string   `json:"name" yaml:"name"`
	URLs          []string `json:"urls" yaml:"urls"`
	Image         string   `json:"image,omitempty" yaml:"image"`
	Repo          string   `json:"repo,omitempty" yaml:"repo"`
	ProtectedPath string   `json:"protected_path,omitempty" yaml:"protected_path"`
}

type serviceImportError struct {
	Row     int    `json:"row"`
	Message string `json:"message"`
}

type servicesImportResponse struct {
	Services []importedService    `json:"services"`
	Errors   []serviceImportError `json:"errors"`
}

func (s *Server) handleServicesParse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxServicesImportBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "services file is larger than 1 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "services file could not be read", http.StatusBadRequest)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	services, rowErrors, err := parseServicesImport(raw, format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(servicesImportResponse{Services: services, Errors: rowErrors})
}

// parseServicesImport parses CSV or YAML (format "csv", "yaml" or "" to
// detect) and validates each row. Invalid rows are reported, not returned.
func parseServicesImport(raw []byte, format string) ([]importedService, []serviceImportError, error) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, fmt.Errorf("services file is empty")
	}
	if format == "" {
		format = detectServicesFormat(raw)
	}
	var rows []importedService
	var err error
	switch format {
	case "csv":
		rows, err = parseServicesCSV(raw)
	case "yaml", "yml":
		rows, err = parseServicesYAML(raw)
	default:
		return nil, nil, fmt.Errorf("unsupported services format %q (use csv or yaml)", format)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(rows) > maxImportedServices {
		return nil, nil, fmt.Errorf("services file lists more than %d services", maxImportedServices)
	}
	services := []importedService{}
	rowErrors := []serviceImportError{}
	seen := map[string]bool{}
	for i, row := range rows {
		if msg := validateImportedService(&row); msg != "" {
			rowErrors = append(rowErrors, serviceImportError{Row: i + 1, Message: msg})
			continue
		}
		key := strings.ToLower(row.Name)
		if seen[key] {
			rowErrors = append(rowErrors, serviceImportError{Row: i + 1, Message: fmt.Sprintf("service name %q is used more than once", row.Name)})
			continue
		}
		seen[key] = true
		services = append(services, row)
	}
	return services, rowErrors, nil
}

func detectServicesFormat(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "services:") || strings.HasPrefix(line, "---") {
			return "yaml"
		}
		if strings.Contains(strings.ToLower(line), "name") && strings.Contains(line, ",") {
			return "csv"
		}
		return "yaml"
	}
	return "csv"
}

func parseServicesCSV(raw []byte) ([]importedService, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	reader.Comment = '#'
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("services CSV is malformed: %v", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("services CSV has no header row")
	}
	columns := map[string]int{}
	for i, header := range records[0] {
		switch strings.ToLower(strings.TrimSpace(header)) {
		case "name", "service":
			columns["name"] = i
		case "url", "urls":
			columns["url"] = i
		case "image":
			columns["image"] = i
		case "repo", "repository", "source":
			columns["repo"] = i
		case "protected_path", "verify_path", "protected path":
			columns["protected_path"] = i
		}
	}
	if _, ok := columns["name"]; !ok {
		return nil, fmt.Errorf("services CSV header must include a name column (name,url,image,repo)")
	}
	cell := func(record []string, column string) string {
		index, ok := columns[column]
		if !ok || index >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[index])
	}
	var rows []importedService
	for _, record := range records[1:] {
		if strings.TrimSpace(strings.Join(record, "")) == "" {
			continue
		}
		rows = append(rows, importedService{
			Name:          cell(record, "name"),
			URLs:          splitServiceURLs(cell(record, "url")),
			Image:         cell(record, "image"),
			Repo:          cell(record, "repo"),
			ProtectedPath: cell(record, "protected_path"),
		})
	}
	return rows, nil
}

func parseServicesYAML(raw []byte) ([]importedService, error) {
	type yamlService struct {
		Name          string   `yaml:"name"`
		URL           string   `yaml:"url"`
		URLs          []string `yaml:"urls"`
		Image         string   `yaml:"image"`
		Repo          string   `yaml:"repo"`
		ProtectedPath string   `yaml:"protected_path"`
	}
	var list []yamlService
	if err := yaml.Unmarshal(raw, &list); err != nil {
		var wrapped struct {
			Services []yamlService `yaml:"services"`
		}
		if wrapErr := yaml.Unmarshal(raw, &wrapped); wrapErr != nil || wrapped.Services == nil {
			return nil, fmt.Errorf("services YAML must be a list of services or a services: list")
		}
		list = wrapped.Services
	}
	rows := make([]importedService, 0, len(list))
	for _, item := range list {
		urls := append([]string(nil), item.URLs...)
		urls = append(urls, splitServiceURLs(item.URL)...)
		rows = append(rows, importedService{Name: strings.TrimSpace(item.Name), URLs: urls, Image: strings.TrimSpace(item.Image), Repo: strings.TrimSpace(item.Repo), ProtectedPath: strings.TrimSpace(item.ProtectedPath)})
	}
	return rows, nil
}

func splitServiceURLs(value string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' }) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func validateImportedService(row *importedService) string {
	row.Name = strings.TrimSpace(row.Name)
	if row.Name == "" || len(row.Name) > 128 || strings.ContainsAny(row.Name, "\r\n\x00") {
		return "service name must be 1–128 printable characters"
	}
	cleaned := row.URLs[:0]
	seen := map[string]bool{}
	for _, raw := range row.URLs {
		raw = strings.TrimSpace(raw)
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Sprintf("%q is not an absolute http(s) URL", raw)
		}
		if !seen[raw] {
			seen[raw] = true
			cleaned = append(cleaned, raw)
		}
	}
	row.URLs = cleaned
	if len(row.URLs) > 20 {
		return "a service may list at most 20 URLs"
	}
	if row.Image != "" && (strings.ContainsAny(row.Image, " \t\r\n") || strings.HasPrefix(row.Image, "-") || len(row.Image) > 512) {
		return fmt.Sprintf("%q is not a valid image reference", row.Image)
	}
	if row.Repo != "" && (strings.ContainsAny(row.Repo, "\r\n\x00") || strings.HasPrefix(row.Repo, "-") || !(strings.HasPrefix(row.Repo, "/") || strings.Contains(row.Repo, "://") || strings.HasPrefix(row.Repo, "git@"))) {
		return fmt.Sprintf("%q is not a repository URL or absolute server path", row.Repo)
	}
	if row.ProtectedPath != "" && !strings.HasPrefix(row.ProtectedPath, "/") {
		return "protected path must start with / (for example /api/me)"
	}
	if row.ProtectedPath != "" && len(row.URLs) == 0 {
		return "a protected path needs at least one service URL"
	}
	if len(row.URLs) == 0 && row.Image == "" && row.Repo == "" {
		return "a service needs at least one URL, image or repository"
	}
	return ""
}

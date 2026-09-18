package web

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

func (s *Server) handleScannerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	available := func(path string) bool { _, err := exec.LookPath(path); return err == nil }
	zapConfigured := strings.TrimSpace(s.cfg.ZAPURL) != ""
	zapHealthy := false
	if zapConfigured {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(strings.TrimRight(s.cfg.ZAPURL, "/") + "/JSON/core/view/version/?apikey=" + url.QueryEscape(s.cfg.ZAPAPIKey))
		if err == nil {
			zapHealthy = resp.StatusCode/100 == 2
			_ = resp.Body.Close()
		}
	}
	gvmConfigured := strings.TrimSpace(s.cfg.GVMHost) != "" || strings.TrimSpace(s.cfg.GVMSocket) != ""
	gvmHealthy := false
	if strings.TrimSpace(s.cfg.GVMSocket) != "" {
		if info, err := os.Stat(s.cfg.GVMSocket); err == nil {
			gvmHealthy = info.Mode()&os.ModeSocket != 0
		}
	} else if strings.TrimSpace(s.cfg.GVMHost) != "" {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.cfg.GVMHost, strconv.Itoa(s.cfg.GVMPort)), 2*time.Second)
		if err == nil {
			gvmHealthy = true
			_ = conn.Close()
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"scanners": []map[string]any{
		{"name": "nuclei", "available": available(s.cfg.NucleiPath), "path": s.cfg.NucleiPath},
		{"name": "zap", "available": zapHealthy, "endpoint_configured": zapConfigured},
		{"name": "openvas", "available": gvmHealthy, "endpoint_configured": gvmConfigured},
		{"name": "trivy", "available": available(s.cfg.TrivyPath), "path": s.cfg.TrivyPath},
		{"name": "vuls", "available": available(s.cfg.VulsPath), "path": s.cfg.VulsPath},
	}})
}

func (s *Server) handleScannerOutput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		http.Error(w, "invalid scanner output path", http.StatusBadRequest)
		return
	}
	scanID := parts[0]
	scanDir, rec := s.findScanByID(scanID)
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	name := ""
	stream := ""
	artifact := false
	if len(parts) >= 4 && parts[1] == "output" {
		name, stream = parts[2], parts[3]
	} else if len(parts) >= 3 && parts[len(parts)-1] == "artifact" {
		name = parts[1]
		artifact = true
	} else {
		http.Error(w, "invalid scanner output path", http.StatusBadRequest)
		return
	}
	var run *scanner.Run
	for i := range rec.ScannerRuns {
		if rec.ScannerRuns[i].Scanner == name {
			run = &rec.ScannerRuns[i]
			break
		}
	}
	if run == nil {
		http.Error(w, "scanner run not found", http.StatusNotFound)
		return
	}
	filePath := ""
	if artifact {
		filePath = run.ArtifactPath
	} else if stream == "stdout" {
		filePath = run.StdoutPath
	} else if stream == "stderr" {
		filePath = run.StderrPath
	} else {
		http.Error(w, "stream must be stdout or stderr", http.StatusBadRequest)
		return
	}
	filePath, ok := safeScannerPath(scanDir, filePath)
	if !ok {
		http.Error(w, "output unavailable", http.StatusNotFound)
		return
	}
	info, err := os.Stat(filePath)
	if err != nil || !info.Mode().IsRegular() {
		http.Error(w, "output unavailable", http.StatusNotFound)
		return
	}
	if artifact {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(filePath)+"\"")
		http.ServeFile(w, r, filePath)
		return
	}
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1<<20 {
		limit = 1 << 20
	}
	if rawTail := strings.TrimSpace(r.URL.Query().Get("tail")); rawTail != "" {
		tail, err := strconv.ParseInt(rawTail, 10, 64)
		if err != nil || tail <= 0 {
			tail = limit
		}
		if tail > 1<<20 {
			tail = 1 << 20
		}
		offset = info.Size() - tail
		if offset < 0 {
			offset = 0
		}
		limit = tail
	}
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "output unavailable", 404)
		return
	}
	defer f.Close()
	_, _ = f.Seek(offset, io.SeekStart)
	data, _ := io.ReadAll(io.LimitReader(f, limit))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Next-Offset", strconv.FormatInt(offset+int64(len(data)), 10))
	_, _ = w.Write(data)
}

func safeScannerPath(scanDir, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(scanDir, path)
	}
	abs, _ := filepath.Abs(path)
	root, _ := filepath.Abs(scanDir)
	rel, err := filepath.Rel(root, abs)
	return abs, err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (s *Server) handleReportAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] != "regenerate" || r.Method != http.MethodPost {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	dir, rec := s.findScanByID(parts[0])
	if rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	if len(rec.ScannerRuns) != len(scanner.OrderedNames) {
		http.Error(w, "all scanner attempts must finish before report regeneration", http.StatusConflict)
		return
	}
	for _, run := range rec.ScannerRuns {
		if !run.Terminal() {
			http.Error(w, "all scanner attempts must finish before report regeneration", http.StatusConflict)
			return
		}
	}
	reportPath := s.generateScannerReport(rec, dir, rec.InstanceID)
	if reportPath == "" {
		http.Error(w, "report generation failed", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ready", "mode": rec.ReportMode, "url": "/api/report/" + rec.ID})
}

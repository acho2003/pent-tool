package recordstore

// PROTOTYPE import: load the existing file-based records under a data directory
// into Postgres. Encrypted credential blobs are stored as bytes (still
// encrypted); scan.json / report.json records are stored as JSON documents.
// Large scanner artifacts are intentionally left on disk.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImportSummary reports how many records of each collection were imported.
type ImportSummary struct {
	Credentials int
	Scans       int
	Reports     int
}

// ImportDataDir walks dataDir and loads credentials and scan/report records into
// the store. It is idempotent: records upsert by id.
func ImportDataDir(ctx context.Context, s *Store, dataDir string) (ImportSummary, error) {
	var sum ImportSummary

	// Encrypted credential blobs: _credentials/<id>.json
	credDir := filepath.Join(dataDir, "_credentials")
	if entries, err := os.ReadDir(credDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			id := strings.TrimSuffix(e.Name(), ".json")
			blob, err := os.ReadFile(filepath.Join(credDir, e.Name()))
			if err != nil {
				return sum, fmt.Errorf("read credential %s: %w", id, err)
			}
			if err := s.PutBytes(ctx, "credentials", id, blob); err != nil {
				return sum, fmt.Errorf("store credential %s: %w", id, err)
			}
			sum.Credentials++
		}
	}

	// Scan records: _assessments/<id>/scan.json and report.json.
	asmtDir := filepath.Join(dataDir, "_assessments")
	dirs, err := os.ReadDir(asmtDir)
	if err != nil {
		return sum, nil // no assessments yet is not an error
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		id := d.Name()
		scanPath := filepath.Join(asmtDir, id, "scan.json")
		if data, err := os.ReadFile(scanPath); err == nil {
			if !json.Valid(data) {
				return sum, fmt.Errorf("scan %s: invalid json", id)
			}
			// Prefer the record's own id when present.
			recID := id
			var head struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(data, &head) == nil && head.ID != "" {
				recID = head.ID
			}
			if err := s.PutJSON(ctx, "scans", recID, data); err != nil {
				return sum, fmt.Errorf("store scan %s: %w", recID, err)
			}
			sum.Scans++
			if rpt, err := os.ReadFile(filepath.Join(asmtDir, id, "report.json")); err == nil && json.Valid(rpt) {
				if err := s.PutJSON(ctx, "reports", recID, rpt); err != nil {
					return sum, fmt.Errorf("store report %s: %w", recID, err)
				}
				sum.Reports++
			}
		}
	}
	return sum, nil
}

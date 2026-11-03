package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const nextjsMapAnalysisLimit = 1 << 20
const nextjsMaxMapAnalyses = 8
const nextjsMaxMapSources = 1000

func nextjsSourceMapJSON(body []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(body), []byte(")]}'")))
}

// Decode embedded sources only. Source paths, sourceRoot, and external sections
// are never resolved or fetched; no source text is persisted.
func nextjsSourceMapContents(body []byte) ([]*string, error) {
	if len(body) > nextjsMapAnalysisLimit {
		return nil, fmt.Errorf("source map exceeds the analysis byte limit")
	}
	var document struct {
		Version  int             `json:"version"`
		Sources  []string        `json:"sources"`
		Contents []*string       `json:"sourcesContent"`
		Mappings *string         `json:"mappings"`
		Sections json.RawMessage `json:"sections"`
	}
	if json.Unmarshal(nextjsSourceMapJSON(body), &document) != nil {
		return nil, fmt.Errorf("source map JSON could not be decoded")
	}
	if len(document.Sections) > 0 && string(document.Sections) != "null" {
		return nil, fmt.Errorf("indexed source map sections are not analyzed")
	}
	if document.Version != 3 || document.Sources == nil || document.Mappings == nil {
		return nil, fmt.Errorf("source map schema is not supported")
	}
	if len(document.Sources) > nextjsMaxMapSources {
		return nil, fmt.Errorf("source map exceeds the embedded source count limit")
	}
	if document.Contents != nil && len(document.Contents) != len(document.Sources) {
		return nil, fmt.Errorf("source map embedded source count does not match its sources")
	}
	return document.Contents, nil
}

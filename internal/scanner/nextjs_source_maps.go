package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const nextjsMapAnalysisLimit = 1 << 20
const nextjsMaxMapAnalyses = 8
const nextjsMaxMapSources = 1000
const nextjsMaxMapDepth = 4
const nextjsMaxMapSections = 64

type nextjsMapSource struct {
	Content  string
	Location string
}

func nextjsSourceMapJSON(body []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(body), []byte(")]}'")))
}

// Decode embedded sources only, including bounded embedded index sections.
// External section/source URLs are never fetched. Valid siblings survive a
// partial analysis; errors contain only fixed diagnostic text, never source.
func nextjsSourceMapContents(body []byte) ([]nextjsMapSource, error) {
	if len(body) > nextjsMapAnalysisLimit {
		return nil, fmt.Errorf("source map exceeds the analysis byte limit")
	}
	var entries []nextjsMapSource
	var gap error
	sources, sections := 0, 0
	report := func(message string) {
		if gap == nil {
			gap = fmt.Errorf("%s", message)
		}
	}
	var walk func(json.RawMessage, int, string)
	walk = func(raw json.RawMessage, depth int, location string) {
		if depth > nextjsMaxMapDepth {
			report("source map exceeds the embedded section depth limit")
			return
		}
		var document struct {
			Version  int               `json:"version"`
			Sources  []string          `json:"sources"`
			Contents []*string         `json:"sourcesContent"`
			Mappings *string           `json:"mappings"`
			Sections []json.RawMessage `json:"sections"`
		}
		if json.Unmarshal(raw, &document) != nil {
			report("source map JSON or field types could not be decoded")
			return
		}
		if document.Version != 3 {
			report("source map version is not supported")
			return
		}
		if document.Sections != nil {
			if document.Sources != nil || document.Mappings != nil || document.Contents != nil {
				report("source map mixes indexed and regular map fields")
				return
			}
			for index, rawSection := range document.Sections {
				if sections >= nextjsMaxMapSections {
					report("source map exceeds the total embedded section count limit")
					break
				}
				sections++
				var section struct {
					Offset *struct {
						Line   *int `json:"line"`
						Column *int `json:"column"`
					} `json:"offset"`
					Map json.RawMessage `json:"map"`
					URL *string         `json:"url"`
				}
				if json.Unmarshal(rawSection, &section) != nil {
					report("source map section fields could not be decoded")
					continue
				}
				if section.URL != nil {
					report("external source map sections are not fetched")
					continue
				}
				if section.Offset == nil || section.Offset.Line == nil || section.Offset.Column == nil || *section.Offset.Line < 0 || *section.Offset.Column < 0 {
					report("source map section offset is missing or invalid")
					continue
				}
				if len(section.Map) == 0 || string(section.Map) == "null" {
					report("source map section has no embedded map")
					continue
				}
				walk(section.Map, depth+1, fmt.Sprintf("%ssections[%d].map.", location, index))
			}
			return
		}
		if document.Sources == nil || document.Mappings == nil {
			report("source map schema is not supported")
			return
		}
		if document.Contents != nil && len(document.Contents) != len(document.Sources) {
			report("source map embedded source count does not match its sources")
			return
		}
		remaining := nextjsMaxMapSources - sources
		count := len(document.Sources)
		if count > remaining {
			count = remaining
			report("source map exceeds the total embedded source count limit")
		}
		sources += count
		for index := 0; index < count && index < len(document.Contents); index++ {
			if document.Contents[index] != nil {
				entries = append(entries, nextjsMapSource{*document.Contents[index], fmt.Sprintf("%ssourcesContent[%d]", location, index)})
			}
		}
	}
	walk(nextjsSourceMapJSON(body), 0, "")
	return entries, gap
}

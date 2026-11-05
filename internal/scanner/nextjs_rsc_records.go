package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Inspect bounded Flight model and text records only. This does not resolve
// references, execute modules, or treat error/debug metadata as resource data.
func nextjsRSCMarker(body []byte, marker string) (bool, error) {
	if len(body) > 64<<10 || !utf8.Valid(body) {
		return false, fmt.Errorf("RSC response exceeds supported text bounds")
	}
	found := false
	var visit func(any, int) error
	visit = func(value any, depth int) error {
		if depth > 32 {
			return fmt.Errorf("RSC model nesting exceeds comparison limit")
		}
		switch value := value.(type) {
		case string:
			found = found || strings.Contains(value, marker)
		case []any:
			for _, item := range value {
				if err := visit(item, depth+1); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, item := range value {
				if err := visit(item, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	records := 0
	streams := map[string]bool{}
	for len(body) > 0 {
		records++
		if records > 2048 {
			return false, fmt.Errorf("RSC record limit exceeded")
		}
		colon := bytes.IndexByte(body, ':')
		if colon < 1 || colon > 8 {
			return false, fmt.Errorf("RSC record identifier unavailable")
		}
		if _, err := strconv.ParseUint(string(body[:colon]), 16, 32); err != nil {
			return false, fmt.Errorf("RSC record identifier invalid")
		}
		recordID := string(body[:colon])
		body = body[colon+1:]
		if len(body) == 0 {
			return false, fmt.Errorf("RSC record truncated")
		}
		tag := body[0]
		if tag == 'T' {
			comma := bytes.IndexByte(body, ',')
			if comma < 2 || comma > 9 {
				return false, fmt.Errorf("RSC text length invalid")
			}
			size, err := strconv.ParseUint(string(body[1:comma]), 16, 32)
			if err != nil || size > uint64(len(body)-comma-1) {
				return false, fmt.Errorf("RSC text record truncated")
			}
			text := body[comma+1 : comma+1+int(size)]
			if !utf8.Valid(text) {
				return false, fmt.Errorf("RSC text encoding invalid")
			}
			found = found || strings.Contains(string(text), marker)
			body = body[comma+1+int(size):]
			continue
		}
		end := bytes.IndexByte(body, '\n')
		if end < 0 {
			return false, fmt.Errorf("RSC line record truncated")
		}
		row := body[:end]
		body = body[end+1:]
		switch tag {
		case 'I', 'H', 'D', 'N': // Module, hint, debug, and timing metadata cannot prove access.
			continue
		case 'X', 'x', 'R', 'r':
			if len(row) != 1 || streams[recordID] {
				return false, fmt.Errorf("RSC stream start is malformed")
			}
			streams[recordID] = true
			continue
		case 'C':
			if !streams[recordID] || len(row) > 1 && !json.Valid(row[1:]) {
				return false, fmt.Errorf("RSC stream close is malformed")
			}
			delete(streams, recordID)
			continue
		case 'E':
			return false, fmt.Errorf("RSC stream contains an error record")
		}
		// Other uppercase tags include binary and stream control records. They
		// require semantics beyond this deliberately bounded model comparison.
		if tag >= 'A' && tag <= 'Z' || tag == '#' || tag == 'r' || tag == 'x' {
			return false, fmt.Errorf("RSC record type is unsupported")
		}
		var value any
		if json.Unmarshal(row, &value) != nil {
			return false, fmt.Errorf("RSC model JSON invalid")
		}
		if err := visit(value, 0); err != nil {
			return false, err
		}
	}
	if len(streams) > 0 {
		return false, fmt.Errorf("RSC stream ended before its close record")
	}
	if records == 0 {
		return false, fmt.Errorf("RSC records unavailable")
	}
	return found, nil
}

func authorizationResponseMarker(representation string, body []byte, marker string) bool {
	if representation == "rsc" {
		found, err := nextjsRSCMarker(body, marker)
		return err == nil && found
	}
	if representation == "html" {
		found, err := nextjsHTMLMarker(body, marker)
		return err == nil && found
	}
	if representation == "pages-json" {
		found, err := nextjsJSONMarker(body, marker)
		return err == nil && found
	}
	return strings.Contains(string(body), marker)
}

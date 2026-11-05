package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Inspect delivered JSON string values without constructing an object tree.
// Duplicate keys are ambiguous evidence, including differently escaped spellings
// of the same decoded key. Diagnostics never include keys or response content.
func nextjsJSONMarker(body []byte, marker string) (bool, error) {
	if len(body) > 64<<10 || !utf8.Valid(body) {
		return false, fmt.Errorf("JSON response exceeds supported text bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	found, nodes := false, 0
	malformed := func() error { return fmt.Errorf("JSON resource response is malformed") }
	var visit func(int) error
	visit = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 8192 {
			return fmt.Errorf("JSON resource nesting or value count exceeds comparison limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return malformed()
		}
		switch value := token.(type) {
		case string:
			found = found || strings.Contains(value, marker)
		case json.Delim:
			switch value {
			case '{':
				keys := map[string]bool{}
				for decoder.More() {
					token, err := decoder.Token()
					if err != nil {
						return malformed()
					}
					key, ok := token.(string)
					if !ok {
						return malformed()
					}
					if keys[key] {
						return fmt.Errorf("JSON resource response has ambiguous duplicate object keys")
					}
					keys[key] = true
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
				closing, err := decoder.Token()
				if err != nil || closing != json.Delim('}') {
					return malformed()
				}
			case '[':
				for decoder.More() {
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
				closing, err := decoder.Token()
				if err != nil || closing != json.Delim(']') {
					return malformed()
				}
			default:
				return malformed()
			}
		}
		return nil
	}
	if err := visit(0); err != nil {
		return false, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false, malformed()
	}
	return found, nil
}

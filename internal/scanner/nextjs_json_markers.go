package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Inspect delivered JSON string values, without treating field names or raw
// serialized syntax as proof that a controlled resource value was returned.
func nextjsJSONMarker(body []byte, marker string) (bool, error) {
	if len(body) > 64<<10 || !utf8.Valid(body) {
		return false, fmt.Errorf("JSON response exceeds supported text bounds")
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		return false, fmt.Errorf("JSON resource response is malformed")
	}
	found, nodes := false, 0
	var visit func(any, int) error
	visit = func(value any, depth int) error {
		nodes++
		if depth > 32 || nodes > 8192 {
			return fmt.Errorf("JSON resource nesting or value count exceeds comparison limit")
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
	if err := visit(value, 0); err != nil {
		return false, err
	}
	return found, nil
}

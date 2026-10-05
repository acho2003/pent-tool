package scanner

import (
	"bytes"
	"encoding/json"
	"github.com/xalgord/xalgorix/v4/internal/storage"
	"os"
	"sort"
)

// Bound structured web artifacts by dropping complete records, never cutting
// JSON mid-token. A true result always requires partial coverage presentation.
func boundWebArtifact(path, scanner string, limit int64) bool {
	if path == "" || limit <= 0 {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() <= limit {
		return false
	}
	switch scanner {
	case "nuclei", "zap", "wapiti", "dalfox":
	default:
		return truncateArtifact(path, limit)
	}
	if info.Size() > 512<<20 {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	if scanner == "nuclei" {
		if int64(len(data)) > limit {
			data = data[:limit]
			last := bytes.LastIndexByte(data, '\n')
			if last < 0 {
				data = nil
			} else {
				data = data[:last+1]
			}
		}
		_ = storage.WriteAtomic(path, data)
		return true
	}
	var value any
	if json.Unmarshal(data, &value) != nil {
		return true
	}
	for int64(len(data)) > limit {
		changed := false
		if rows, ok := value.([]any); ok && len(rows) > 0 {
			value = rows[:len(rows)-1]
			changed = true
		}
		if root, ok := value.(map[string]any); ok {
			if rows, ok := root["alerts"].([]any); ok && len(rows) > 0 {
				root["alerts"] = rows[:len(rows)-1]
				changed = true
			}
			if groups, ok := root["vulnerabilities"].(map[string]any); ok {
				keys := make([]string, 0, len(groups))
				for key := range groups {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					if rows, ok := groups[key].([]any); ok && len(rows) > 0 {
						groups[key] = rows[:len(rows)-1]
						changed = true
						break
					}
				}
			}
		}
		if !changed {
			break
		}
		data, err = json.Marshal(value)
		if err != nil {
			return true
		}
	}
	if int64(len(data)) <= limit {
		_ = storage.WriteAtomic(path, data)
	}
	return true
}

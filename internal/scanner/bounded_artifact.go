package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// Retain complete records within the byte budget. Errors leave the original
// artifact available for diagnosis, but callers must not report usable success.
func boundWebArtifact(path, scanner string, limit int64) (bool, error) {
	if path == "" || limit <= 0 {
		return false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if info.Size() <= limit {
		return false, nil
	}
	switch scanner {
	case "nuclei":
		file, err := os.Open(path)
		if err != nil {
			return true, err
		}
		defer file.Close()
		reader := bufio.NewReader(io.LimitReader(file, limit+1))
		var retained bytes.Buffer
		for {
			line, readErr := reader.ReadBytes('\n')
			if int64(retained.Len()+len(line)) > limit {
				break
			}
			if len(bytes.TrimSpace(line)) > 0 {
				if !json.Valid(bytes.TrimSpace(line)) {
					return true, fmt.Errorf("invalid JSONL record in retained artifact")
				}
				retained.Write(line)
			}
			if readErr != nil {
				if readErr != io.EOF {
					return true, readErr
				}
				break
			}
		}
		return true, storage.WriteAtomic(path, retained.Bytes())
	case "openvas":
		return boundXMLArtifact(path, limit)
	case "zap", "wapiti", "dalfox", "vuls":
	default:
		return truncateArtifact(path, limit), nil
	}
	if info.Size() > 512<<20 {
		return true, fmt.Errorf("structured artifact exceeds 512 MiB parsing limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return true, err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return true, fmt.Errorf("invalid structured artifact: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return true, fmt.Errorf("structured artifact has trailing data")
	}
	type recordGroup struct {
		rows []any
		set  func([]any)
	}
	var groups []recordGroup
	if rows, ok := value.([]any); ok {
		groups = append(groups, recordGroup{rows, func(rows []any) { value = rows }})
	}
	if root, ok := value.(map[string]any); ok {
		if rows, ok := root["alerts"].([]any); ok {
			groups = append(groups, recordGroup{rows, func(rows []any) { root["alerts"] = rows }})
		}
		for _, field := range []string{"scannedCves", "ScannedCves"} {
			if records, ok := root[field].(map[string]any); ok {
				keys := make([]string, 0, len(records))
				for key := range records {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				rows := make([]any, len(keys))
				for i, key := range keys {
					rows[i] = records[key]
				}
				groups = append(groups, recordGroup{rows, func(rows []any) {
					retained := map[string]any{}
					for i, row := range rows {
						retained[keys[i]] = row
					}
					root[field] = retained
				}})
			}
		}
		if vulnerabilities, ok := root["vulnerabilities"].(map[string]any); ok {
			keys := make([]string, 0, len(vulnerabilities))
			for key := range vulnerabilities {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if rows, ok := vulnerabilities[key].([]any); ok {
					groups = append(groups, recordGroup{rows, func(rows []any) { vulnerabilities[key] = rows }})
				}
			}
		}
	}
	total := 0
	for _, group := range groups {
		total += len(group.rows)
	}
	encode := func(count int) ([]byte, error) {
		for _, group := range groups {
			take := min(count, len(group.rows))
			group.set(group.rows[:take])
			count -= take
		}
		return json.Marshal(value)
	}
	baseline, err := encode(0)
	if err != nil {
		return true, err
	}
	if int64(len(baseline)) > limit {
		return true, fmt.Errorf("artifact metadata cannot fit configured %d-byte limit", limit)
	}
	// Binary search bounds serialization to O(log N) passes instead of deleting
	// one finding and reserializing the entire report on each iteration.
	low, high := 0, total
	retained := baseline
	for low < high {
		middle := low + (high-low+1)/2
		candidate, err := encode(middle)
		if err != nil {
			return true, err
		}
		if int64(len(candidate)) <= limit {
			low, retained = middle, candidate
		} else {
			high = middle - 1
		}
	}
	return true, storage.WriteAtomic(path, retained)
}

// Keep the native XML structure and complete result elements. The original
// result counts remain native metadata; the run explicitly records incompleteness.
func boundXMLArtifact(path string, limit int64) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return true, err
	}
	if info.Size() > 512<<20 {
		return true, fmt.Errorf("XML artifact exceeds 512 MiB parsing limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return true, err
	}
	defer file.Close()
	decoder := xml.NewDecoder(file)
	type tokenRecord struct {
		token  xml.Token
		record int
	}
	var tokens []tokenRecord
	var stack []xml.Name
	current, total := -1, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return true, fmt.Errorf("invalid XML artifact: %w", err)
		}
		if len(tokens) >= 1000000 {
			return true, fmt.Errorf("XML artifact exceeds token parsing limit")
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Local == "result" && len(stack) > 0 && stack[len(stack)-1].Local == "results" {
				current = total
				total++
			}
			stack = append(stack, element.Name)
		}
		tokens = append(tokens, tokenRecord{xml.CopyToken(token), current})
		if element, ok := token.(xml.EndElement); ok {
			stack = stack[:len(stack)-1]
			if element.Name.Local == "result" && len(stack) > 0 && stack[len(stack)-1].Local == "results" {
				current = -1
			}
		}
	}
	encode := func(count int) ([]byte, error) {
		var out bytes.Buffer
		encoder := xml.NewEncoder(&out)
		for _, item := range tokens {
			if item.record < 0 || item.record < count {
				if err := encoder.EncodeToken(item.token); err != nil {
					return nil, err
				}
			}
		}
		if err := encoder.Flush(); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	baseline, err := encode(0)
	if err != nil {
		return true, err
	}
	if int64(len(baseline)) > limit {
		return true, fmt.Errorf("XML metadata cannot fit configured %d-byte limit", limit)
	}
	low, high := 0, total
	retained := baseline
	for low < high {
		middle := low + (high-low+1)/2
		candidate, err := encode(middle)
		if err != nil {
			return true, err
		}
		if int64(len(candidate)) <= limit {
			low, retained = middle, candidate
		} else {
			high = middle - 1
		}
	}
	return true, storage.WriteAtomic(path, retained)
}

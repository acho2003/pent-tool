package scanner

import (
	"fmt"
	"strings"
)

const nextjsMaxMappingSegments = 100000

type nextjsOriginalPosition struct{ Line, Column int64 }

// Validate delta-encoded v3 positions without retaining source names or content.
// Positions are local to their regular map (including embedded index sections).
func nextjsSourceMappings(mapping string, sourceCount, nameCount int, budget *int) (map[int]nextjsOriginalPosition, error) {
	positions := map[int]nextjsOriginalPosition{}
	source, line, column, name := int64(0), int64(0), int64(0), int64(0)
	fail := func() (map[int]nextjsOriginalPosition, error) {
		return nil, fmt.Errorf("source map mapping segments are invalid or exceed supported bounds")
	}
	if mapping == "" {
		return positions, nil
	}
	for _, generatedLine := range strings.Split(mapping, ";") {
		generated := int64(0)
		if generatedLine == "" {
			continue
		}
		for _, segment := range strings.Split(generatedLine, ",") {
			if *budget <= 0 {
				return fail()
			}
			*budget--
			values := make([]int64, 0, 5)
			for index := 0; index < len(segment); {
				var value uint64
				shift := uint(0)
				for {
					if index >= len(segment) || shift > 30 {
						return fail()
					}
					digit := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", segment[index])
					index++
					if digit < 0 {
						return fail()
					}
					value |= uint64(digit&31) << shift
					if value > 1<<32-1 {
						return fail()
					}
					if digit&32 == 0 {
						break
					}
					shift += 5
				}
				// The special signed minimum encoding is outside these position bounds.
				if value == 1 {
					return fail()
				}
				signed := int64(value >> 1)
				if value&1 != 0 {
					signed = -signed
				}
				values = append(values, signed)
				if len(values) > 5 {
					return fail()
				}
			}
			if len(values) != 1 && len(values) != 4 && len(values) != 5 {
				return fail()
			}
			if values[0] < 0 {
				return fail()
			}
			generated += values[0]
			if generated > 1<<31-1 {
				return fail()
			}
			if len(values) == 1 {
				continue
			}
			source += values[1]
			line += values[2]
			column += values[3]
			if source < 0 || source >= int64(sourceCount) || line < 0 || line > 1<<31-1 || column < 0 || column > 1<<31-1 {
				return fail()
			}
			if len(values) == 5 {
				name += values[4]
				if name < 0 || name >= int64(nameCount) {
					return fail()
				}
			}
			if _, exists := positions[int(source)]; !exists {
				positions[int(source)] = nextjsOriginalPosition{line, column}
			}
		}
	}
	return positions, nil
}

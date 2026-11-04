package scanner

import (
	"strings"
	"testing"
)

func TestNextjsRSCMarkerBoundedRecords(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		found, gap bool
	}{
		{"model", "0:[\"$\",\"div\",null,{\"children\":\"PRIVATE_42\"}]\n", true, false},
		{"escaped", "0:{\"children\":\"PRIV\\u0041TE_42\"}\n", true, false},
		{"text", "1:Ta,PRIVATE_420:null\n", true, false},
		{"debug", "1:D{\"name\":\"PRIVATE_42\"}\n0:null\n", false, false},
		{"key", "0:{\"PRIVATE_42\":false}\n", false, false},
		{"iterable", "1:X\n1:\"PRIVATE_42\"\n1:C\n", true, false},
		{"open-stream", "1:X\n0:\"PRIVATE_42\"\n", false, true},
		{"invalid-close", "1:C\n", false, true},
		{"error", "0:\"PRIVATE_42\"\n1:E{\"message\":\"failed\"}\n", false, true},
		{"binary", "1:Aa,PRIVATE_42", false, true},
		{"truncated", "0:\"PRIVATE_42\"", false, true},
		{"truncated-text", "1:Tff,PRIVATE_42", false, true},
		{"invalid-id", "xx:null\n", false, true},
		{"depth", "0:" + strings.Repeat("[", 34) + "null" + strings.Repeat("]", 34) + "\n", false, true},
		{"bytes", strings.Repeat("x", (64<<10)+1), false, true},
		{"records", strings.Repeat("0:null\n", 2049), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := nextjsRSCMarker([]byte(tc.body), "PRIVATE_42")
			if found != tc.found || (err != nil) != tc.gap {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
}

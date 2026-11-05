package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNextjsJSONMarkerDecodesOnlyBoundedStringValues(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		found, gap bool
	}{
		{"nested", `{"pageProps":{"record":"PRIVATE_42"}}`, true, false},
		{"escaped", `{"pageProps":{"record":"PRIV\u0041TE_42"}}`, true, false},
		{"array", `[null,42,{"records":["PRIVATE_42"]}]`, true, false},
		{"key-only", `{"PRIVATE_42":false}`, false, false},
		{"key-escaped", `{"PRIV\u0041TE_42":null}`, false, false},
		{"duplicate-last-private", `{"record":null,"record":"PRIVATE_42"}`, false, true},
		{"duplicate-first-private", `{"record":"PRIVATE_42","record":null}`, false, true},
		{"duplicate-escaped-key", `{"record":null,"rec\u006frd":"PRIVATE_42"}`, false, true},
		{"nested-duplicate", `{"child":{"record":null,"record":"PRIVATE_42"}}`, false, true},
		{"independent-keys", `[{"record":"PRIVATE_42"},{"record":null}]`, true, false},
		{"duplicate-no-private", `{"record":null,"record":false}`, false, true},
		{"large-number", `{"number":1e999,"record":"PRIVATE_42"}`, true, false},
		{"multiple-values", `"PRIVATE_42" null`, false, true},
		{"empty", ``, false, true},
		{"split", `["PRIVATE_","42"]`, false, false},
		{"truncated", `{"record":"PRIVATE_42"`, false, true},
		{"trailing", `{"record":"PRIVATE_42"} extra`, false, true},
		{"encoding", string([]byte{'"', 255, '"'}), false, true},
		{"depth", strings.Repeat("[", 34) + `"PRIVATE_42"` + strings.Repeat("]", 34), false, true},
		{"nodes", "[" + strings.Repeat("null,", 8192) + `"PRIVATE_42"]`, false, true},
		{"bytes", `"` + strings.Repeat("x", 64<<10) + `PRIVATE_42"`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := nextjsJSONMarker([]byte(tc.body), "PRIVATE_42")
			if err != nil && strings.Contains(err.Error(), "PRIVATE_42") {
				t.Fatal("response value leaked in diagnostics")
			}
			if found != tc.found || (err != nil) != tc.gap {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
}

func TestNextjsJSONMarkerControlledAccessComparison(t *testing.T) {
	for _, mode := range []string{"escaped", "key-only", "malformed", "depth", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if r.Header.Get("Authorization") == "Bearer owner-secret" {
					fmt.Fprint(w, `{"pageProps":{"record":"CONTROLLED_RESOURCE_1"}}`)
					return
				}
				switch mode {
				case "escaped":
					fmt.Fprint(w, `{"pageProps":{"record":"CONTROLLED\u005fRESOURCE_1"}}`)
				case "key-only":
					fmt.Fprint(w, `{"CONTROLLED_RESOURCE_1":false}`)
				case "malformed":
					fmt.Fprint(w, `{"record":"CONTROLLED_RESOURCE_1"`)
				case "duplicate":
					fmt.Fprint(w, `{"record":null,"record":"CONTROLLED_RESOURCE_1"}`)
				case "depth":
					fmt.Fprint(w, strings.Repeat("[", 34)+`"CONTROLLED_RESOURCE_1"`+strings.Repeat("]", 34))
				}
			}))
			defer server.Close()
			req, cfg := webComparisonFixture(t, server.URL, "pages-json", true)
			run := Run{Scanner: "apichecks"}
			var findings []Finding
			checked, gaps, err := runAuthorizationComparisons(t.Context(), req, cfg, &run, func(f Finding) error { findings = append(findings, f); return nil })
			if err != nil || len(run.AuthorizationResults) != 2 {
				t.Fatalf("comparison failed: %v %+v", err, run)
			}
			result := run.AuthorizationResults[1]
			if mode == "escaped" {
				if checked != 2 || gaps != 0 || len(findings) != 1 || !result.MarkerConfirmed || result.Observed != "allow" {
					t.Fatalf("escaped access missed: checked=%d gaps=%d findings=%v result=%+v", checked, gaps, findings, result)
				}
			} else if checked != 1 || gaps != 1 || len(findings) != 0 || result.Status != "unknown" || result.MarkerConfirmed {
				t.Fatalf("unsupported evidence proved access: checked=%d gaps=%d findings=%v result=%+v", checked, gaps, findings, result)
			}
			if mode == "duplicate" && !strings.Contains(result.Reason, "duplicate") {
				t.Fatal("ambiguous JSON was not identified")
			}
			if (mode == "malformed" || mode == "depth" || mode == "duplicate") && !strings.Contains(result.Reason, "JSON") {
				t.Fatal("JSON comparison gap not explained")
			}
		})
	}
}

func TestNextjsJSONMarkerCacheBoundaryUsesDecodedValues(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		private    bool
	}{
		{"escaped", `{"record":"PRIVATE\u005fCONTROLLED_42"}`, true},
		{"key-only", `{"PRIVATE_CONTROLLED_42":false}`, false},
		{"malformed", `{"record":"PRIVATE_CONTROLLED_42"`, false},
		{"duplicate", `{"record":null,"record":"PRIVATE_CONTROLLED_42"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := cacheBoundaryManifest("https://owned.example.test")
			response := boundaryResponse{status: 200, header: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}, body: []byte(tc.body)}
			if boundaryPrivate(fixture, response) != tc.private {
				t.Fatal("JSON cache comparison used encoded bytes or keys")
			}
		})
	}
}

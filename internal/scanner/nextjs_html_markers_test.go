package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNextjsHTMLMarkerDecodedValuesAndBounds(t *testing.T) {
	var attributes strings.Builder
	for i := 0; i < 1025; i++ {
		fmt.Fprintf(&attributes, `data-x%d="x" `, i)
	}
	for _, tc := range []struct {
		name, body string
		found, gap bool
	}{
		{"text", `<p>PRIVATE_42</p>`, true, false},
		{"numeric", `<p>PRIVATE&#95;42</p>`, true, false},
		{"hex", `<p>PRIVATE&#x5f;42</p>`, true, false},
		{"attribute", `<div data-record="PRIVATE&#95;42"></div>`, true, false},
		{"duplicate-attribute", `<div data-record="public" data-record="PRIVATE_42"></div>`, false, false},
		{"comment", `<!-- PRIVATE_42 -->`, false, false},
		{"attribute-name", `<div PRIVATE_42="false"></div>`, false, false},
		{"script-delivery", `<script>window.data="PRIVATE_42"</script>`, true, false},
		{"raw-script-entity", `<script>window.data="PRIVATE&#95;42"</script>`, false, false},
		{"split-nodes", `<p>PRIVATE_<b>42</b></p>`, false, false},
		{"truncated", `<p>PRIVATE_42</p><div data-record="unfinished`, false, true},
		{"tokens", strings.Repeat(`<p>x</p>`, 3000), false, true},
		{"attributes", `<div ` + attributes.String() + `>PRIVATE_42</div>`, false, true},
		{"bytes", strings.Repeat("x", (64<<10)+1), false, true},
		{"encoding", string([]byte{255}), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := nextjsHTMLMarker([]byte(tc.body), "PRIVATE_42")
			if found != tc.found || (err != nil) != tc.gap {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
}

func TestNextjsHTMLMarkerControlledAccessComparison(t *testing.T) {
	for _, mode := range []string{"encoded", "comment", "attribute-name", "raw-script"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.Header.Get("Authorization") == "Bearer owner-secret" {
					fmt.Fprint(w, `<p>CONTROLLED_RESOURCE_1</p>`)
					return
				}
				switch mode {
				case "encoded":
					fmt.Fprint(w, `<p>CONTROLLED&#95;RESOURCE_1</p>`)
				case "comment":
					fmt.Fprint(w, `<!-- CONTROLLED_RESOURCE_1 --><p>Public</p>`)
				case "attribute-name":
					fmt.Fprint(w, `<div CONTROLLED_RESOURCE_1="false">Public</div>`)
				case "raw-script":
					fmt.Fprint(w, `<script>window.data="CONTROLLED&#95;RESOURCE_1"</script>`)
				}
			}))
			defer server.Close()
			req, cfg := webComparisonFixture(t, server.URL, "html", true)
			run := Run{Scanner: "apichecks"}
			var findings []Finding
			checked, gaps, err := runAuthorizationComparisons(t.Context(), req, cfg, &run, func(f Finding) error { findings = append(findings, f); return nil })
			if err != nil || len(run.AuthorizationResults) != 2 {
				t.Fatalf("comparison failed: %v", err)
			}
			result := run.AuthorizationResults[1]
			if mode == "encoded" {
				if checked != 2 || gaps != 0 || len(findings) != 1 || !result.MarkerConfirmed {
					t.Fatalf("encoded access missed: %d %d %v %+v", checked, gaps, findings, result)
				}
			} else if checked != 1 || gaps != 1 || len(findings) != 0 || result.Status != "unknown" {
				t.Fatalf("non-value proved access: %d %d %v %+v", checked, gaps, findings, result)
			}
		})
	}
}

func TestNextjsHTMLMarkerCacheBoundaryDecodedValues(t *testing.T) {
	fixture := cacheBoundaryManifest("https://owned.example.test")
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`<p>PRIVATE&#95;CONTROLLED_42</p>`, true},
		{`<!-- PRIVATE_CONTROLLED_42 -->`, false},
		{`<div PRIVATE_CONTROLLED_42="false"></div>`, false},
	} {
		response := boundaryResponse{status: 200, header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, body: []byte(tc.body)}
		if boundaryPrivate(fixture, response) != tc.want {
			t.Fatal("HTML cache comparison did not use decoded values")
		}
	}
}

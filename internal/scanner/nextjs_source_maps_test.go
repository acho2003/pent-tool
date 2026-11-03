package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNextjsSourceMapContentsSchemaAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"nullable", `{"version":3,"sources":[null,"a.ts"],"sourcesContent":[null,"public"],"mappings":""}`, true},
		{"external-only", `{"version":3,"sources":["https://external.test/source"],"mappings":""}`, true},
		{"prefixed", ")]}'\n" + `{"version":3,"sources":[],"mappings":""}`, true},
		{"truncated", `{"version":3,"sources":[],"mappings":`, false},
		{"version", `{"version":2,"sources":[],"mappings":""}`, false},
		{"mismatched", `{"version":3,"sources":[],"sourcesContent":["secret"],"mappings":""}`, false},
		{"type", `{"version":3,"sources":["a"],"sourcesContent":[42],"mappings":""}`, false},
		{"indexed", `{"version":3,"sections":[{"url":"https://external.test/map"}]}`, false},
		{"oversized", strings.Repeat(" ", nextjsMapAnalysisLimit+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := nextjsSourceMapContents([]byte(tc.body))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
	sources := make([]string, nextjsMaxMapSources+1)
	body, _ := json.Marshal(map[string]any{"version": 3, "sources": sources, "mappings": ""})
	if _, err := nextjsSourceMapContents(body); err == nil {
		t.Fatal("source count cap ignored")
	}
}

func TestNextjsSourceMapDecodesPrivateKeyAndKeepsCandidatesUnrequested(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for _, tc := range []struct {
		name          string
		deep, private bool
	}{{"ordinary", false, true}, {"deep-private", true, true}, {"deep-public", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			content := strings.Repeat("/* padding */", 500) + `const url='/api/from-map?token=source-only-secret';` + `const NEXT_PUBLIC_API_URL='https://public.test';`
			if tc.private {
				content += encoded
			} else {
				content += "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----"
			}
			body, _ := json.Marshal(map[string]any{"version": 3, "sources": []string{"https://source.test/private-file.ts"}, "sourceRoot": "https://source.test/", "sourcesContent": []string{content}, "mappings": ""})
			// A complete JSON decode is required: the raw response has no PEM dashes.
			body = []byte(strings.ReplaceAll(string(body), "-", `\u002d`))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					t.Error("credentials forwarded to public asset")
				}
				switch r.URL.Path {
				case "/":
					fmt.Fprint(w, `<script>self.__next_f=[]</script><script src='/_next/static/main.js'></script>`)
				case "/_next/static/main.js":
					fmt.Fprint(w, "//# sourceMappingURL=main.js.map\n")
				case "/_next/static/main.js.map":
					w.Write(body)
				default:
					t.Errorf("unrequested source or API URL fetched: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			req := nextjsTestRequest(t, server.URL+"/")
			if tc.deep {
				req.Profile = ProfileNextjsDeep
			}
			req.TargetAuth = "Cookie: synthetic-session=secret"
			run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			keys := 0
			for _, f := range findings {
				if f.RuleID == "nextjs-public-private-key" {
					keys++
					if !strings.Contains(f.Evidence, "sourcesContent[0]") {
						t.Fatal("missing decoded-source evidence")
					}
				}
			}
			expected := 0
			if tc.deep && tc.private {
				expected = 1
			}
			if keys != expected {
				t.Fatalf("keys=%d expected=%d", keys, expected)
			}
			candidates := 0
			for _, c := range run.HistoricalCandidates {
				if c.Source == "source_map_api_reference" {
					candidates++
					if c.State != EndpointStateHistoricalUnverified || strings.Contains(c.URL, "source-only-secret") {
						t.Fatal("source-map candidate is not safely unverified")
					}
				}
			}
			if (candidates > 0) != tc.deep {
				t.Fatalf("deep=%v candidates=%d", tc.deep, candidates)
			}
			artifact, _ := os.ReadFile(run.ArtifactPath)
			events, _ := os.ReadFile(run.CoverageEventsPath)
			metadata, _ := json.Marshal(run)
			for _, secret := range []string{strings.Split(encoded, "\n")[1], "source-only-secret", "private-file.ts", "/* padding */"} {
				if strings.Contains(string(artifact)+string(events)+string(metadata), secret) {
					t.Fatal("source content persisted")
				}
			}
		})
	}
}

func TestNextjsSourceMapAnalysisCapAndTruncationArePartial(t *testing.T) {
	for _, mode := range []string{"count", "bytes", "indexed", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			count := 1
			if mode == "count" {
				count = nextjsMaxMapAnalyses + 1
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					fmt.Fprint(w, `<script>self.__next_f=[]</script>`)
					for i := 0; i < count; i++ {
						fmt.Fprintf(w, `<script src='/_next/static/%d.js'></script>`, i)
					}
					return
				}
				if strings.HasSuffix(r.URL.Path, ".js") {
					fmt.Fprint(w, "console.log('public')")
					return
				}
				if strings.HasSuffix(r.URL.Path, ".map") {
					switch mode {
					case "bytes":
						fmt.Fprintf(w, `{"version":3,"sources":["a"],"sourcesContent":["%s"],"mappings":""}`, strings.Repeat("x", nextjsMapAnalysisLimit))
					case "indexed":
						fmt.Fprint(w, `{"version":3,"sections":[{"url":"https://external.test/map"}]}`)
					case "malformed":
						fmt.Fprint(w, `{"version":3,"sources":[],"mappings":""}trailing`)
					default:
						fmt.Fprint(w, `{"version":3,"sources":["a"],"sourcesContent":["public"],"mappings":""}`)
					}
					return
				}
				t.Error("unexpected map source fetch")
				http.NotFound(w, r)
			}))
			defer server.Close()
			req := nextjsTestRequest(t, server.URL+"/")
			req.Profile = ProfileNextjsDeep
			run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
			if run.Status != "completed" || run.Outcome != "PARTIAL" || run.Completeness != "partial" {
				t.Fatalf("map analysis gap hidden: %+v", run)
			}
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			maps := 0
			for _, f := range findings {
				if f.RuleID == "nextjs-source-map" {
					maps++
				}
				if f.Severity == "high" {
					t.Fatal("false secret finding")
				}
			}
			if maps != count {
				t.Fatalf("map exposure evidence lost: got %d want %d", maps, count)
			}
		})
	}
}

func TestNextjsSourceMapFindingsSurviveLaterBudgetFailureWithChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<script>self.__next_f=[]</script><script src='/_next/static/a.js'></script><script src='/_next/static/b.js'></script>`)
		case "/_next/static/a.js":
			fmt.Fprint(w, "console.log('public')")
		case "/_next/static/a.js.map":
			fmt.Fprint(w, `{"version":3,"sources":["a"],"sourcesContent":["public"],"mappings":""}`)
		default:
			t.Error("request budget was exceeded")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	req := nextjsTestRequest(t, server.URL+"/")
	req.Profile = ProfileNextjsDeep
	req.Nextjs.MaxRequests = 3
	run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
	if run.Status != "failed" || run.GapKind != GapBudgetExhausted {
		t.Fatalf("expected bounded partial run: %+v", run)
	}
	findings, errs := ParseRuns([]Run{run})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	found := false
	for _, finding := range findings {
		if finding.RuleID == "nextjs-source-map" {
			found = true
			if finding.EvidenceCompleteness != "partial" {
				t.Fatal("incomplete run was labeled complete")
			}
		}
	}
	if !found {
		t.Fatal("confirmed map finding lost after the later budget failure")
	}
	file, err := os.OpenFile(run.ArtifactPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString("\n")
	file.Close()
	findings, errs = ParseRuns([]Run{run})
	if len(findings) != 0 || len(errs) == 0 {
		t.Fatal("tampered partial evidence was accepted")
	}
}

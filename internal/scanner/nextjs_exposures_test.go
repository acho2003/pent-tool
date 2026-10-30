package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNextjsDeepConfirmsPublicPrivateKeyWithoutRetainingIt(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	payload, _ := json.Marshal(map[string]string{"accidentalKey": encoded})
	for _, deep := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "deep"}[deep], func(t *testing.T) {
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Write([]byte(`<script>self.__next_f=[]</script><script src='/_next/static/main.js'></script>`))
					return
				}
				if strings.HasSuffix(r.URL.Path, ".js") {
					w.Write(payload)
					return
				}
				http.NotFound(w, r)
			}))
			defer lab.Close()
			req := nextjsTestRequest(t, lab.URL+"/")
			if deep {
				req.Profile = ProfileNextjsDeep
			}
			run := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{}, nil)
			findings, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range findings {
				if finding.RuleID == "nextjs-public-private-key" {
					found = true
					if finding.Severity != "high" || finding.EvidenceRef == "" {
						t.Fatalf("finding: %+v", finding)
					}
				}
			}
			if found != deep {
				t.Fatalf("deep=%v findings=%+v", deep, findings)
			}
			artifact, _ := os.ReadFile(run.ArtifactPath)
			events, _ := os.ReadFile(run.CoverageEventsPath)
			secretLine := strings.Split(encoded, "\n")[1]
			if strings.Contains(string(artifact)+string(events), secretLine) {
				t.Fatal("private key material persisted")
			}
		})
	}
}

func TestNextjsPublicConfigurationAndFakePEMAreNotSecrets(t *testing.T) {
	for _, body := range []string{`const NEXT_PUBLIC_API_URL="https://api.test"`, "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----", `{"sources":[],"mappings":"token secret password"}`} {
		if finding := nextjsPrivateKeyFinding(Request{}, "https://app.test/main.js", []byte(body), ""); finding != nil {
			t.Fatalf("false positive: %+v", finding)
		}
	}
}

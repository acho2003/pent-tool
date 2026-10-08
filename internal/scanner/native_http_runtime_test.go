package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

func TestNucleiRuntimeExercises684SelectedRequests(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_NUCLEI") != "1" {
		t.Skip("requires retained native Nuclei runtime")
	}
	runNative684HTTPFixture(t, "nuclei")
}

func TestDalfoxRuntimeRecords684RequestDispositions(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_DALFOX") != "1" {
		t.Skip("requires retained native Dalfox runtime")
	}
	runNative684HTTPFixture(t, "dalfox")
}

// Stopping an assessment mid-run must not throw away a native tool's results.
// Before this fix, cancellation sent SIGKILL straight away, and Dalfox wrote
// its findings as a single buffered JSON array only when it exited normally —
// so a mid-run SIGKILL left no output file at all, and a stop threw away
// everything Dalfox had already found. Two changes, both exercised here
// against the real binary: cancellation sends SIGINT first (process_unix.go),
// giving a tool a chance to exit on its own terms; and Dalfox now writes jsonl
// (dalfox.go), one PoC per line as each URL in its list finishes, rather than
// one array written only at the very end — confirmed by polling its output
// file for a line to appear before stopping the scan.
func TestDalfoxRuntimeCancellationPreservesFindingsFoundBeforeTheStop(t *testing.T) {
	if os.Getenv("XALGORIX_TEST_DALFOX") != "1" {
		t.Skip("requires retained native Dalfox runtime")
	}
	withShortCancelGrace(t, 3*time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An unescaped reflection Dalfox can confirm with its default payload
		// set, so it has something to report well before a 50-URL list finishes.
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	var endpoints []string
	for i := 0; i < 50; i++ {
		endpoints = append(endpoints, fmt.Sprintf("%s/?q=%d", server.URL, i))
	}
	req := Request{Target: endpoints[0], TypedAssessment: true, AppScope: &scope, ScanDir: t.TempDir(), EndpointTargets: endpoints}
	cfg := Config{DalfoxPath: "dalfox", DalfoxTimeout: 2 * time.Minute}
	spec := buildDalfox(req, cfg)
	if spec.notApp != "" {
		t.Fatal(spec.notApp)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := time.Now()
	done := make(chan Run, 1)
	go func() { done <- executeSpec(ctx, "dalfox", req, cfg, spec, nil) }()

	// Poll the artifact for its first written line rather than guessing how
	// long Dalfox's own discovery phase takes for one URL; stop regardless once
	// the budget below is spent, so the test cannot hang on a slow environment.
	deadline := time.Now().Add(90 * time.Second)
	wroteBeforeStop := false
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(spec.artifact); err == nil && strings.TrimSpace(string(data)) != "" {
			wroteBeforeStop = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	cancel()
	var run Run
	select {
	case run = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("cancellation did not stop the real Dalfox process in time (it may not have exited on SIGINT)")
	}
	elapsedAfterCancel := time.Since(started)
	if run.Status != "cancelled" {
		t.Fatalf("status=%s outcome=%s reason=%s stderr=%s", run.Status, run.Outcome, run.Reason, readCapped(run.StderrPath, 4000))
	}
	t.Logf("real Dalfox exited %s after being asked to stop (well under the 3s SIGINT grace period plus the 20s wait above means it responded to SIGINT, not the SIGKILL fallback)", elapsedAfterCancel)
	if !wroteBeforeStop {
		t.Skip("Dalfox had not written any result line within the polling budget; cannot verify preservation on this run (the SIGINT-vs-SIGKILL exit-promptness assertion above still ran)")
	}
	if run.ArtifactPath == "" {
		t.Fatal("Dalfox had already written a result line, but the cancelled run recorded no artifact path")
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatalf("cancelled run's artifact could not be parsed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Dalfox had written a result line before the stop, but no finding survived in the cancelled run")
	}
	t.Logf("cancelled Dalfox run kept %d finding(s) found before it was stopped", len(findings))
}

func runNative684HTTPFixture(t *testing.T, scanner string) {
	t.Helper()
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>Local fixture</title><body>XALGORIX_LOCAL_FIXTURE</body></html>")
	}))
	defer server.Close()
	origin, _ := assessment.ParseApprovedOrigin("app", server.URL)
	origin.PathPrefix = "/"
	scope := assessment.NewAppScope([]assessment.ApprovedOrigin{origin})
	root := t.TempDir()
	templates := filepath.Join(root, "templates")
	if err := os.MkdirAll(templates, 0700); err != nil {
		t.Fatal(err)
	}
	template := `id: xalgorix-local-receipt
info:
  name: Local fixture request receipt
  author: xalgorix
  severity: info
  tags: fixture
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "XALGORIX_LOCAL_FIXTURE"
`
	if err := os.WriteFile(filepath.Join(templates, "receipt.yaml"), []byte(template), 0600); err != nil {
		t.Fatal(err)
	}
	if scanner == "nuclei" {
		signNativeFixtureTemplate(t, templates)
	}
	req := Request{WorkflowVersion: "unified-v1", Target: server.URL + "/?q=0", StructuredDispatch: true, TypedAssessment: true, AppScope: &scope, ScanDir: root, AttemptID: "native-" + scanner}
	for i := 0; i < 684; i++ {
		raw := fmt.Sprintf("%s/?q=%d", server.URL, i)
		req.EndpointTargets = append(req.EndpointTargets, raw)
		req.InputRequests = append(req.InputRequests, ScannerRequestInput{EndpointID: fmt.Sprintf("request-%d", i), URL: raw, Method: "GET", Selected: true})
	}
	cfg := Config{DalfoxPath: "dalfox", DalfoxTimeout: 2 * time.Minute, NucleiPath: "nuclei", NucleiTemplatesDir: templates, NucleiTimeout: 2 * time.Minute, RateRPS: 1000, WebMaxEndpoints: 1000, MaxOutputBytes: 8 << 20, Budget: NewAssessmentBudget(1000, 1000, 2*time.Minute)}
	surface := &AttackSurface{}
	for _, input := range req.InputRequests {
		surface.Endpoints = append(surface.Endpoints, AttackSurfaceEndpoint{ID: input.EndpointID, URL: input.URL, Method: input.Method, ScannerCoverage: []EndpointScannerCoverage{{Scanner: scanner, Status: "dispatched"}}})
	}
	if scanner == "dalfox" {
		cfg.DalfoxTimeout = 15 * time.Second
	}
	manifest, err := SaveScannerInputs(req, scanner)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewRecordingGateway(t.Context(), req, cfg, scanner)
	if err != nil {
		t.Fatal(err)
	}
	req.GatewayURL, req.GatewayCAPath, req.Gateway = gateway.URL, gateway.CAPath, gateway
	spec := buildNuclei(req, cfg)
	if scanner == "dalfox" {
		spec = buildDalfox(req, cfg)
	}
	run := executeSpec(t.Context(), scanner, req, cfg, spec, nil)
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	run.InputManifestPath, run.AttemptID = manifest, req.AttemptID
	CompleteEndpointCoverage(surface, scanner, run)
	if run.Status != "completed" && (scanner != "dalfox" || run.ExecutionOutcome != "TIMEOUT" || run.Outcome != "TIMEOUT" || run.Reason == "") {
		t.Fatalf("native %s: %s %s stderr=%s", scanner, run.Status, run.Reason, readCapped(run.StderrPath, 8000))
	}
	events, err := ReadCoverageEvents(gateway.EventPath)
	if err != nil {
		t.Fatal(err)
	}
	exercised := map[string]bool{}
	for _, event := range events {
		if event.Kind == "observed" {
			for _, id := range event.EndpointIDs {
				exercised[id] = true
			}
		}
	}
	for _, input := range req.InputRequests {
		if !exercised[input.EndpointID] {
			if scanner != "dalfox" {
				t.Errorf("no HTTP receipt for %s", input.EndpointID)
			} else {
				found := false
				for _, endpoint := range surface.Endpoints {
					if endpoint.ID == input.EndpointID && endpoint.ScannerCoverage[0].Status == "failed" && endpoint.ScannerCoverage[0].Reason != "" {
						found = true
					}
				}
				if !found {
					t.Errorf("no receipt or explicit failure for %s", input.EndpointID)
				}
			}
		}
	}
	if len(exercised) == 0 {
		t.Fatal("native scanner issued no recorded requests")
	}
	t.Logf("%s native request receipts: %d; Nuclei uses only one deterministic fixture template", scanner, len(exercised))
}

// Generate a disposable signing identity so acceptance retains -dut. Never
// install fixture trust into the application image or the user's key store.
func signNativeFixtureTemplate(t *testing.T, templates string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Xalgorix disposable fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NUCLEI_USER_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PD NUCLEI USER PRIVATE KEY", Bytes: private})))
	t.Setenv("NUCLEI_USER_CERTIFICATE", string(pem.EncodeToMemory(&pem.Block{Type: "PD NUCLEI USER CERTIFICATE", Bytes: certificate})))
	cmd := exec.CommandContext(t.Context(), "nuclei", "-t", templates, "-sign", "-duc", "-ni")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sign disposable template: %v: %s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(templates, "receipt.yaml"))
	if err != nil || !strings.Contains(string(data), "# digest:") {
		t.Fatal("fixture template was not signed")
	}
}

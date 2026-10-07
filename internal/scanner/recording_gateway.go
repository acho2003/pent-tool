package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

type CoverageEvent struct {
	AttemptID    string   `json:"attempt_id"`
	Scanner      string   `json:"scanner"`
	EndpointIDs  []string `json:"endpoint_ids,omitempty"`
	URL          string   `json:"url,omitempty"`
	Method       string   `json:"method,omitempty"`
	Phase        string   `json:"phase"`
	Kind         string   `json:"kind"`
	At           string   `json:"at"`
	ResponseCode int      `json:"response_code,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	NativeRef    string   `json:"native_reference,omitempty"`
}

type RecordingGateway struct {
	req                Request
	cfg                Config
	scanner            string
	server             *http.Server
	cancel             context.CancelFunc
	closing            bool
	connections        map[net.Conn]bool
	workers            sync.WaitGroup
	listener           net.Listener
	client             *http.Client
	key                *ecdsa.PrivateKey
	ca                 *x509.Certificate
	certificates       map[string]*tls.Certificate
	username, password string
	mu                 sync.Mutex
	encoder            *json.Encoder
	file               *os.File
	failed             error
	limitations        map[string]bool
	formFuzzInFlight   sync.WaitGroup
	formFuzzObserved   int
	formFuzzUncertain  bool
	formFuzzArmed      bool
	formFuzzRequests   int
	requests           int
	phase              string
	URL                string
	CAPath             string
	EventPath          string
}

func NewRecordingGateway(ctx context.Context, req Request, cfg Config, scanner string) (*RecordingGateway, error) {
	if req.AppScope == nil {
		return nil, fmt.Errorf("recording gateway requires approved scope")
	}
	if err := os.MkdirAll(req.ScanDir, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &RecordingGateway{cancel: cancel, connections: map[net.Conn]bool{}, req: req, cfg: cfg, scanner: scanner, certificates: map[string]*tls.Certificate{}, phase: "active_test"}
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	g.username = "attempt"
	g.password = hex.EncodeToString(token)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	g.key = key
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Xalgorix attempt recording CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	g.ca, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	g.CAPath = filepath.Join(req.ScanDir, "recording-ca.pem")
	if err := os.WriteFile(g.CAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	g.EventPath = filepath.Join(req.ScanDir, "coverage-events.jsonl")
	g.file, err = os.OpenFile(g.EventPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	g.encoder = json.NewEncoder(g.file)
	bind := "127.0.0.1:0"
	advertise := os.Getenv("XALGORIX_SCANNER_GATEWAY_HOST")
	if advertise != "" {
		bind = "0.0.0.0:0"
	} else {
		advertise = "127.0.0.1"
	}
	g.listener, err = net.Listen("tcp", bind)
	if err != nil {
		g.file.Close()
		return nil, err
	}
	_, port, _ := net.SplitHostPort(g.listener.Addr().String())
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(advertise, port), User: url.UserPassword(g.username, g.password)}
	g.URL = u.String()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = g.guardedDial
	g.client = &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	g.server = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	for _, input := range req.InputRequests {
		kind := "selected"
		if !input.Selected {
			kind = "skipped"
		}
		g.record(CoverageEvent{Kind: kind, URL: input.URL, Method: input.Method, EndpointIDs: []string{input.EndpointID}, Reason: input.Reason, Phase: "routing"})
	}
	go g.server.Serve(g.listener)
	return g, nil
}

// guardedDial resolves the upstream host itself, rejects it when the scope
// guard blocks any resolved address (for example a name that now points at the
// scanner host or dashboard listener), and connects to the addresses it
// checked so a second lookup cannot return something different.
func (g *RecordingGateway) guardedDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addresses []string
	if ip := net.ParseIP(host); ip != nil {
		addresses = []string{ip.String()}
	} else {
		resolved, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if lookupErr != nil {
			return nil, lookupErr
		}
		for _, entry := range resolved {
			addresses = append(addresses, entry.IP.String())
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	if g.cfg.ScopeGuard != nil {
		if blocked, reason := g.cfg.ScopeGuard("http://"+address+"/", addresses); blocked {
			g.record(CoverageEvent{Kind: "blocked", URL: "http://" + address + "/", Reason: reason})
			return nil, fmt.Errorf("blocked by scope guard")
		}
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, address := range addresses {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address, port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func (g *RecordingGateway) Close() error {
	g.mu.Lock()
	g.closing = true
	g.cancel()
	for conn := range g.connections {
		_ = conn.Close()
	}
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = g.server.Shutdown(ctx)
	g.workers.Wait()
	g.client.CloseIdleConnections()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.file != nil {
		if err := g.file.Sync(); err != nil {
			g.failed = err
		}
		g.file.Close()
		g.file = nil
	}
	return g.failed
}
func (g *RecordingGateway) ArmFormFuzz() { g.mu.Lock(); g.formFuzzArmed = true; g.mu.Unlock() }
func (g *RecordingGateway) UpdateTargetAuth(headers []string) {
	g.mu.Lock()
	g.req.TargetAuth = strings.Join(headers, "\n")
	g.mu.Unlock()
}
func (g *RecordingGateway) SetPhase(phase string) { g.mu.Lock(); g.phase = phase; g.mu.Unlock() }
func (g *RecordingGateway) record(event CoverageEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.req.WapitiPostApproval != nil && event.Method == "POST" {
		if event.Kind == "observed" {
			g.formFuzzObserved++
		}
		if event.Kind == "failed" {
			g.formFuzzUncertain = true
		}
	}
	event.Scanner, event.AttemptID, event.At = g.scanner, g.req.AttemptID, time.Now().UTC().Format(time.RFC3339Nano)
	if event.Phase == "" {
		event.Phase = g.phase
	}
	if event.Kind == "blocked" || event.Kind == "failed" {
		if g.limitations == nil {
			g.limitations = map[string]bool{}
		}
		if len(g.limitations) < 16 {
			g.limitations[event.Reason] = true
		}
	}
	event.URL = SafeTelemetryURL(event.URL)
	if g.file != nil {
		if err := g.encoder.Encode(event); err != nil {
			g.failed = err
		}
	}
}
func (g *RecordingGateway) authorization(r *http.Request) bool {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(g.username+":"+g.password))
	return r.Header.Get("Proxy-Authorization") == expected
}
func (g *RecordingGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		http.Error(w, "attempt closed", 503)
		return
	}
	g.workers.Add(1)
	g.mu.Unlock()
	defer g.workers.Done()
	if !g.authorization(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Xalgorix attempt"`)
		http.Error(w, "proxy authorization required", 407)
		return
	}
	if r.Method == "CONNECT" {
		g.connect(w, r)
		return
	}
	g.forward(w, r)
}
func (g *RecordingGateway) connect(w http.ResponseWriter, r *http.Request) {
	raw := "https://" + r.Host + "/"
	origin, err := assessment.ParseApprovedOrigin("", raw)
	if err != nil {
		http.Error(w, "invalid CONNECT", 400)
		return
	}
	allowed := false
	for _, o := range g.req.AppScope.Origins() {
		if o.Scheme == origin.Scheme && o.Host == origin.Host && o.Port == origin.Port {
			allowed = true
		}
	}
	if !allowed {
		g.record(CoverageEvent{Kind: "blocked", Method: "CONNECT", URL: raw, Reason: "origin not approved"})
		http.Error(w, "origin not approved", 403)
		return
	}
	cert, err := g.certificate(origin.Host)
	if err != nil {
		http.Error(w, "certificate unavailable", 500)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", 500)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		conn.Close()
		return
	}
	g.connections[conn] = true
	g.mu.Unlock()
	defer func() { conn.Close(); g.mu.Lock(); delete(g.connections, conn); g.mu.Unlock() }()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if secure.Handshake() != nil {
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(secure))
	if err != nil {
		return
	}
	request = request.WithContext(r.Context())
	request.URL.Scheme = "https"
	request.URL.Host = r.Host
	// The tunnel is bound to its approved authority; ignore forged Host headers.
	request.Host = r.Host
	recorder := &gatewayResponse{header: make(http.Header)}
	g.forward(recorder, request)
	response := &http.Response{StatusCode: recorder.status, Header: recorder.header, Body: io.NopCloser(strings.NewReader(recorder.body.String())), ContentLength: int64(recorder.body.Len()), Close: true, ProtoMajor: 1, ProtoMinor: 1}
	if response.StatusCode == 0 {
		response.StatusCode = 200
	}
	response.Write(secure)
}

type gatewayResponse struct {
	header http.Header
	status int
	body   strings.Builder
}

func (w *gatewayResponse) Header() http.Header    { return w.header }
func (w *gatewayResponse) WriteHeader(status int) { w.status = status }
func (w *gatewayResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(data)
}

func (g *RecordingGateway) forward(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.String()
	event := CoverageEvent{URL: raw, Method: r.Method}
	if g.req.WapitiPostApproval != nil && r.Method != "POST" && (raw != g.req.WapitiPostURL || (r.Method != "GET" && r.Method != "HEAD")) {
		g.record(CoverageEvent{Kind: "blocked", URL: raw, Method: r.Method, Reason: "form fuzzing is restricted to its approved entry point"})
		http.Error(w, "request outside form operation", 403)
		return
	}

	if r.Method == http.MethodPost {
		if r.Body == nil {
			r.Body = http.NoBody
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		if r.Body != nil {
			_ = r.Body.Close()
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		selected := false
		for _, input := range g.req.InputRequests {
			if input.Selected && input.ReadOnly && input.Method == r.Method && input.URL == raw && input.BodyDigest != "" && input.BodyDigest == bodyDigest(string(body)) {
				selected = true
				break
			}
		}
		approvedFuzz, fuzzReason := false, ""
		if err == nil {
			approvedFuzz, fuzzReason = g.admitFormFuzzDecision(raw, r.Header.Get("Content-Type"), body)
		}
		if approvedFuzz {
			defer g.formFuzzInFlight.Done()
			event.NativeRef = "approved-form-fuzz:" + fuzzApprovalID(*g.req.WapitiPostApproval)
		}
		if err != nil || len(body) > 2<<20 || (!approvedFuzz && (!selected || browserDiscoveryRequestAllowed(g.req, g.cfg, r.Method, raw, r.Header.Get("Content-Type"), body) != nil)) {
			reason := "POST does not match an approved read-only request"
			if fuzzReason != "" {
				reason = fuzzReason
			}
			g.record(CoverageEvent{Kind: "blocked", URL: raw, Method: r.Method, Reason: reason})
			http.Error(w, "POST outside approved policy", 403)
			return
		}
	}
	if err := browserRequestAllowed(g.req, g.cfg, r.Method, raw); err != nil && r.Method != http.MethodPost {
		event.Kind, event.Reason = "blocked", err.Error()
		g.record(event)
		http.Error(w, "request outside approved policy", 403)
		return
	}
	g.mu.Lock()
	g.requests++
	failed := g.failed
	requestLimit := g.cfg.WebMaxEndpoints * 100
	if g.req.ZAPDiscoveryOnly {
		requestLimit = g.cfg.WebMaxEndpoints
	}
	over := requestLimit > 0 && g.requests > requestLimit
	g.mu.Unlock()
	if failed != nil || over {
		event.Kind, event.Reason = "blocked", "recording or request budget unavailable"
		g.record(event)
		http.Error(w, "recording/request budget unavailable", 429)
		return
	}
	if err := g.cfg.Budget.Wait(r.Context()); err != nil {
		event.Kind, event.Reason = "blocked", "assessment budget exhausted"
		g.record(event)
		http.Error(w, "assessment budget exhausted", 429)
		return
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		_ = r.Body.Close()
		if err != nil || len(body) > 2<<20 {
			event.Kind, event.Reason = "blocked", "request body exceeds recording budget"
			g.record(event)
			http.Error(w, "request body unavailable", 413)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	bodySum := sha256.Sum256(body)
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Host = request.URL.Host
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	g.mu.Lock()
	boundHeaders := g.req.TargetAuth
	g.mu.Unlock()
	bound, _ := assessment.ParseApprovedOrigin("", g.req.Target)
	o, _ := assessment.ParseApprovedOrigin("", raw)
	sameOrigin := bound.Scheme == o.Scheme && bound.Host == o.Host && bound.Port == o.Port
	for _, h := range strings.Split(boundHeaders, "\n") {
		name, _, ok := strings.Cut(h, ":")
		if ok {
			request.Header.Del(strings.TrimSpace(name))
		}
	}
	if !sameOrigin {
		request.Header.Del("Authorization")
		request.Header.Del("Cookie")
	}
	if sameOrigin {
		for _, h := range strings.Split(boundHeaders, "\n") {
			name, value, ok := strings.Cut(h, ":")
			if ok {
				request.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
			}
		}
	}
	requestOrigin, _ := assessment.ParseApprovedOrigin("", raw)
	for _, input := range g.req.InputRequests {
		if !input.Selected || input.Method != r.Method || !gatewayInputAuthenticationMatches(input, request, boundHeaders, sameOrigin, g.req.AuthContextID) {
			continue
		}
		candidate, e := url.Parse(input.URL)
		candidateOrigin, e2 := assessment.ParseApprovedOrigin("", input.URL)
		if (len(body) > 0 && input.BodyDigest == "") || (input.BodyDigest != "" && input.BodyDigest != hex.EncodeToString(bodySum[:])) {
			continue
		}
		if input.ContentType != "" && !strings.EqualFold(strings.TrimSpace(input.ContentType), strings.TrimSpace(r.Header.Get("Content-Type"))) {
			continue
		}
		if e == nil && e2 == nil && candidateOrigin.Scheme == requestOrigin.Scheme && candidateOrigin.Host == requestOrigin.Host && candidateOrigin.Port == requestOrigin.Port && candidate.EscapedPath() == r.URL.EscapedPath() && candidate.RawQuery == r.URL.RawQuery && candidate.ForceQuery == r.URL.ForceQuery {
			event.EndpointIDs = append(event.EndpointIDs, input.EndpointID)
		}
	}
	event.Kind = "requested"
	g.record(event)
	response, err := g.client.Do(request)
	if err != nil {
		event.Kind, event.Reason = "failed", "upstream request failed"
		g.record(event)
		http.Error(w, "upstream unavailable", 502)
		return
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		event.Kind, event.Reason = "failed", "upstream response exceeds recording limit"
		g.record(event)
		http.Error(w, "response limit exceeded", 502)
		return
	}
	for key, values := range response.Header {
		if strings.EqualFold(key, "Connection") {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(response.StatusCode)
	w.Write(data)
	event.Kind, event.ResponseCode = "observed", response.StatusCode
	g.record(event)
}
func (g *RecordingGateway) certificate(host string) (*tls.Certificate, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cert := g.certificates[host]; cert != nil {
		return cert, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, g.ca, &g.key.PublicKey, g.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: g.key}
	g.certificates[host] = cert
	return cert, nil
}

// ApplyOutcome keeps blocked/failed traffic visible even when the scanner
// process itself exits successfully. Call after Close seals the event journal.
func (g *RecordingGateway) ApplyOutcome(run *Run) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.limitations) == 0 {
		return
	}
	reasons := make([]string, 0, len(g.limitations))
	for reason := range g.limitations {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		run.Limitations = append(run.Limitations, RunLimitation{Kind: "gateway_restriction", Reason: reason})
	}
	run.Completeness = "partial"
	if run.Status == "completed" {
		run.Outcome = "PARTIAL"
	}
}

// A response received with credentials cannot prove exercise of the anonymous
// request variant at the same URL. Only the context represented by the actual
// outgoing headers can receive the receipt.
func gatewayInputAuthenticationMatches(input ScannerRequestInput, request *http.Request, boundHeaders string, sameOrigin bool, contextIDs ...string) bool {
	bound := sameOrigin && strings.TrimSpace(boundHeaders) != ""
	if input.AuthContextID == "" {
		if bound || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			return false
		}
		return true
	}
	if bound {
		if len(contextIDs) > 0 && contextIDs[0] != "" {
			return input.AuthContextID == contextIDs[0]
		}
		return input.AuthContextID == inventoryID(input.InventoryScope, "target-bound")
	}
	matched := false
	for name, expected := range input.Headers {
		if sensitiveTelemetryKey(name) {
			if expected == "" || request.Header.Get(name) != expected {
				return false
			}
			matched = true
		}
	}
	return matched
}

package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/xalgord/xalgorix/v4/internal/apifixture"
)

type observedMultipartAction struct {
	body                  []byte
	contentType, actionID string
}

// An owned loopback proxy receives Chromium's original HTTP body and stops
// the POST before the action. CDP PostData is not used because it can omit files.
func observeFrameworkMultipart(t *testing.T, base, chrome string) observedMultipartAction {
	t.Helper()
	captured := make(chan observedMultipartAction, 1)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.String()
		if !strings.HasPrefix(raw, base+"/") {
			http.Error(w, "outside owned fixture", 403)
			return
		}
		if r.Method == "POST" && raw == base+"/multipart" {
			body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			if err == nil && len(body) <= 65536 {
				select {
				case captured <- observedMultipartAction{body, r.Header.Get("Content-Type"), r.Header.Get("Next-Action")}:
				default:
				}
			}
			w.WriteHeader(204)
			return
		}
		if r.Method != "GET" {
			http.Error(w, "unapproved fixture request", 403)
			return
		}
		forwarded := r.Clone(r.Context())
		forwarded.RequestURI = ""
		response, err := client.Do(forwarded)
		if err != nil {
			http.Error(w, "fixture unavailable", 502)
			return
		}
		defer response.Body.Close()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	}))
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	launch := launcher.New().Context(ctx).Bin(chrome).UserDataDir(t.TempDir()).Headless(true).NoSandbox(true).Leakless(false).Set("proxy-server", receiver.URL).Set("proxy-bypass-list", "<-loopback>")
	control, err := launch.Launch()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { launch.Kill(); launch.Cleanup() }()
	browser := rod.New().Context(ctx).ControlURL(control)
	if err := browser.Connect(); err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	if err = page.Navigate(base + "/multipart"); err != nil {
		t.Fatal(err)
	}
	if err = page.WaitLoad(); err != nil {
		t.Fatal(err)
	}
	page.WaitRequestIdle(time.Second, nil, nil, nil)()
	file := filepath.Join(t.TempDir(), "synthetic.bin")
	if err = os.WriteFile(file, []byte{0, 255, 42, 13, 10}, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := page.Element(`input[name="attachment"]`)
	if err != nil {
		t.Fatal(err)
	}
	if err = input.SetFiles([]string{file}); err != nil {
		t.Fatal(err)
	}
	button, err := page.Element(`button[type="submit"]`)
	if err != nil {
		t.Fatal(err)
	}
	if err = button.Click(proto.InputMouseButtonLeft, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case action := <-captured:
		if !nextjsActionIDPattern.MatchString(action.actionID) || ValidateNextjsActionBody(action.contentType, action.body) != nil || !bytes.Contains(action.body, []byte{0, 255, 42, 13, 10}) {
			t.Fatalf("real multipart capture invalid: action ID=%v framing=%v binary=%v bytes=%d", nextjsActionIDPattern.MatchString(action.actionID), ValidateNextjsActionBody(action.contentType, action.body), bytes.Contains(action.body, []byte{0, 255, 42, 13, 10}), len(action.body))
		}
		return action
	case <-ctx.Done():
		t.Fatal("real multipart action capture timed out")
	}
	return observedMultipartAction{}
}

func frameworkMultipartCampaign(t *testing.T, base, chrome string) (Run, []Finding) {
	t.Helper()
	wire := observeFrameworkMultipart(t, base, chrome)
	req, cfg := actionFixture(t, base)
	frameworkIdentities(&req, base)
	meta, err := (apifixture.Store{Dir: req.APIFixtureDir}).Put(bytes.NewReader(wire.body), wire.contentType)
	if err != nil {
		t.Fatal(err)
	}
	manifest := NextjsActionFixture{URL: base + "/multipart", ActionID: wire.actionID, BodyRef: meta.Ref, ContentType: wire.contentType, VerificationURL: base + "/api/state", ReadyMarker: "CONTROLLED_READY_42", ChangedMarker: "CONTROLLED_CHANGED_42", CleanupURL: base + "/api/reset", CleanupMethod: "DELETE"}
	req.NextjsActionApprovals[0].FixtureRef = replaceFrameworkFixture(t, &req, manifest)
	run := (nextjsActionsRunner{}).Run(t.Context(), req, cfg, nil)
	found, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	return run, found
}

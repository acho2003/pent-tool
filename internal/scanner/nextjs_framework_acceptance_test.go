package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
)

type frameworkLabRow struct {
	SharedWith string `json:"shared_with,omitempty"`
	Variant    string `json:"variant"`
	Check      string `json:"check"`
	Findings   int    `json:"findings"`
	Requests   int    `json:"recorded_requests"`
	Passed     bool   `json:"passed"`
	Outcome    string `json:"outcome,omitempty"`
}

func frameworkLabURL(t *testing.T, variable string) string {
	t.Helper()
	raw := os.Getenv(variable)
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Scheme != "http" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("%s must be a loopback HTTP origin", variable)
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !addr.IsLoopback() {
		t.Fatalf("%s must use an explicit loopback IP", variable)
	}
	return strings.TrimSuffix(u.String(), "/")
}
func frameworkGet(t *testing.T, raw, cookie string) []byte {
	t.Helper()
	request, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	client := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("lab prerequisite failed: HTTP %d %v", response.StatusCode, err)
	}
	return body
}

// frameworkRSCResource observes the framework's canonical RSC URL without
// following redirects. Only the owned path and its _rsc query may be returned.
func frameworkRSCResource(t *testing.T, base string) string {
	t.Helper()
	endpoint := base + "/resource"
	request, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header = authorizationRepresentationHeaders("rsc")
	request.Header.Set("Cookie", "lab-role=owner")
	client := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected the pinned framework's canonical RSC redirect, got HTTP %d", response.StatusCode)
	}
	location, err := response.Location()
	approved, _ := url.Parse(base)
	if err != nil || location.Scheme != approved.Scheme || location.Host != approved.Host || location.User != nil || location.Path != "/resource" || location.Fragment != "" {
		t.Fatal("RSC canonical URL left the owned resource")
	}
	query, err := url.ParseQuery(location.RawQuery)
	if err != nil || len(query) != 1 || len(query["_rsc"]) != 1 {
		t.Fatal("RSC canonical URL did not supply exactly one _rsc query")
	}
	return location.String()
}

func frameworkIdentities(req *Request, base string) {
	for i := range req.AuthContexts {
		identity := req.AuthContexts[i].Identity
		req.AuthContexts[i].Headers = []string{"Cookie: lab-role=" + identity}
		req.AuthContexts[i].Refresh = func(ctx context.Context, headers []string) ([]string, error) {
			request, err := http.NewRequestWithContext(ctx, "GET", base+"/api/session", nil)
			if err != nil {
				return nil, err
			}
			for _, line := range headers {
				key, value, ok := strings.Cut(line, ":")
				if ok {
					request.Header.Set(strings.TrimSpace(key), strings.TrimSpace(value))
				}
			}
			client := http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, err := client.Do(request)
			if err != nil {
				return nil, err
			}
			defer response.Body.Close()
			var session struct {
				Role string `json:"role"`
			}
			if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&session) != nil || session.Role != identity {
				return nil, fmt.Errorf("lab identity verification failed")
			}
			return slices.Clone(headers), nil
		}
	}
}
func replaceFrameworkFixture(t *testing.T, req *Request, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := (apifixture.Store{Dir: req.APIFixtureDir}).Put(bytes.NewReader(raw), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	return meta.Ref
}
func frameworkRecordedRequests(run Run) int {
	events, _ := ReadCoverageEvents(run.CoverageEventsPath)
	count := 0
	for _, event := range events {
		if event.Kind == "observed" {
			count++
		}
	}
	return count
}

func TestNextjsFrameworkAcceptance(t *testing.T) {
	if os.Getenv("XALGORIX_NEXTJS_LAB_VULNERABLE_URL") == "" && os.Getenv("XALGORIX_NEXTJS_LAB_PATCHED_URL") == "" {
		t.Skip("run test/nextjs-lab/run.py for pinned production Next.js acceptance")
	}
	t.Setenv("XALGORIX_UNIFIED_WORKFLOW", "1")
	collector := frameworkLabURL(t, "XALGORIX_NEXTJS_LAB_COLLECTOR_URL")
	var rows []frameworkLabRow
	t.Cleanup(func() {
		if output := os.Getenv("XALGORIX_NEXTJS_LAB_RESULTS"); output != "" {
			body, err := json.MarshalIndent(struct {
				Schema int               `json:"schema_version"`
				Nextjs string            `json:"nextjs"`
				React  string            `json:"react"`
				Passed bool              `json:"passed"`
				Cases  []frameworkLabRow `json:"cases"`
			}{1, "16.4.3", "19.3.1", !t.Failed(), rows}, "", "  ")
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(output, body, 0600); err != nil {
				t.Error(err)
			}
		}
	})
	record := func(variant, name string, count, expected int, run Run) {
		requests := frameworkRecordedRequests(run)
		passed := count == expected && run.Status == "completed" && requests > 0
		shared := ""
		if name == "built-in-action-origin-control" {
			shared = "server-action-authorization"
			requests = 0
		}
		rows = append(rows, frameworkLabRow{Variant: variant, Check: name, Findings: count, Requests: requests, Passed: passed, Outcome: run.Outcome, SharedWith: shared})
		if !passed {
			t.Errorf("%s %s: got %d findings, want %d; run=%+v", variant, name, count, expected, run)
		}
	}
	for _, variant := range []string{"vulnerable", "patched"} {
		base := frameworkLabURL(t, "XALGORIX_NEXTJS_LAB_"+strings.ToUpper(variant)+"_URL")
		var info struct {
			Fixture  string `json:"fixture"`
			Variant  string `json:"variant"`
			Callback string `json:"callback"`
		}
		if json.Unmarshal(frameworkGet(t, base+"/api/lab-info", ""), &info) != nil || info.Fixture != "xalgorix-nextjs-lab-v1" || info.Variant != variant || info.Callback != collector {
			t.Fatal("URL is not the owned matching lab fixture")
		}
		want := 0
		if variant == "vulnerable" {
			want = 1
		}
		req := nextjsTestRequest(t, base+"/")
		req.Profile = ProfileNextjsDeep
		assets := (nextjsAssetsRunner{}).Run(t.Context(), req, Config{Budget: NewAssessmentBudget(0, 2000, 0)}, nil)
		findings, err := ParseRun(assets)
		if err != nil {
			t.Fatal(err)
		}
		maps := 0
		for _, f := range findings {
			if f.RuleID == "nextjs-source-map" {
				maps++
			}
		}
		if maps > 0 {
			maps = 1
		}
		record(variant, "production-source-map", maps, want, assets)
		html := frameworkGet(t, base+"/legacy", "lab-role=owner")
		build := nextjsBuildIDPattern.FindSubmatch(html)
		if build == nil {
			t.Fatal("Pages Router build ID not observed")
		}
		rscResource := frameworkRSCResource(t, base)
		for _, comparison := range []struct {
			representation string
			anonymous      bool
			name           string
		}{
			{"html", true, "html-access"},
			{"pages-json", true, "pages-json-access"},
			{"rsc", true, "rsc-anonymous-access"},
			{"rsc", false, "rsc-reader-access"},
		} {
			representation := comparison.representation
			access, cfg := webComparisonFixture(t, base, representation, comparison.anonymous)
			frameworkIdentities(&access, base)
			endpoint := base + "/legacy"
			if representation == "pages-json" {
				endpoint = base + "/_next/data/" + string(build[1]) + "/legacy.json"
			} else if representation == "rsc" {
				endpoint = rscResource
			}
			ref := replaceFrameworkFixture(t, &access, AuthorizationResourceFixture{URL: endpoint, ResponseMarker: "PRIVATE_CONTROLLED_42", Representation: representation})
			for i := range access.AuthorizationExpectations {
				access.AuthorizationExpectations[i].ResourceFixtureRef = ref
			}
			access.Inventory = NewSeedAttackSurface(access.Scope, access.Target)
			addAuthorizationRequestVariants(access.Inventory, access)
			access.EndpointTargets = DispatchTargets(access.Inventory, "apichecks", 100)
			access.InputRequests = BuildScannerInputs(access.Inventory, access, "apichecks")
			run := Run{Scanner: "apichecks"}
			var found []Finding
			checked, gaps, err := runAuthorizationComparisons(t.Context(), access, cfg, &run, func(f Finding) error { found = append(found, f); return nil })
			if err != nil {
				t.Fatal(err)
			}
			run.Status, run.Outcome = "completed", "SUCCESS_NO_FINDINGS"
			if len(found) > 0 {
				run.Outcome = "SUCCESS_WITH_FINDINGS"
			}
			if checked != 2 || gaps != 0 {
				run.Status, run.Outcome = "failed", "PARTIAL"
				t.Errorf("framework access comparison incomplete: checked=%d gaps=%d", checked, gaps)
			}
			record(variant, comparison.name, len(found), want, run)
		}
		account := frameworkGet(t, base+"/account", "")
		actionID := regexp.MustCompile(`name="\$ACTION_ID_([a-fA-F0-9]{40,64})"`).FindSubmatch(account)
		if actionID == nil {
			t.Fatal("Server Action reference was not observed in the real rendered form")
		}
		action, cfg := actionFixture(t, base)
		frameworkIdentities(&action, base)
		body, err := (apifixture.Store{Dir: action.APIFixtureDir}).Put(strings.NewReader("[]"), "text/plain")
		if err != nil {
			t.Fatal(err)
		}
		manifest := NextjsActionFixture{URL: base + "/account", ActionID: string(actionID[1]), BodyRef: body.Ref, ContentType: "text/plain;charset=UTF-8", VerificationURL: base + "/api/state", ReadyMarker: "CONTROLLED_READY_42", ChangedMarker: "CONTROLLED_CHANGED_42", CleanupURL: base + "/api/reset", CleanupMethod: "DELETE"}
		action.NextjsActionApprovals[0].FixtureRef = replaceFrameworkFixture(t, &action, manifest)
		actionRun := (nextjsActionsRunner{}).Run(t.Context(), action, cfg, nil)
		found, err := ParseRun(actionRun)
		if err != nil {
			t.Fatal(err)
		}
		if actionRun.Status != "completed" {
			t.Errorf("%s action campaign incomplete: %+v", variant, actionRun)
		}
		actionWant := 0
		if variant == "vulnerable" {
			actionWant = 2
		}
		record(variant, "server-action-authorization", len(found), actionWant, actionRun)
		originFindings := 0
		for _, f := range found {
			if f.RuleID == "nextjs-action-origin" {
				originFindings++
			}
		}
		record(variant, "built-in-action-origin-control", originFindings, 0, actionRun)
		cache := cacheBoundaryManifest(base)
		cache.URL, cache.BypassURL, cache.CleanupURL = base+"/api/cache", base+"/api/cache?uncached=1", base+"/api/reset"
		for _, fixture := range []NextjsBoundaryFixture{cache, {Kind: "redirect", URL: base + "/api/redirect?next=%2Faccount", Parameter: "next", ControlValue: "/account", DestinationURL: collector + "/sink"}, {Kind: "proxy", URL: base + "/api/proxy?url=%2Fcontrolled", Parameter: "url", CallbackURL: collector + "/hit", EventsURL: collector + "/events"}} {
			boundary, cfg := boundaryFixture(t, base, fixture, collector)
			frameworkIdentities(&boundary, base)
			run := (nextjsBoundariesRunner{}).Run(t.Context(), boundary, cfg, nil)
			found, err := ParseRun(run)
			if err != nil {
				t.Fatal(err)
			}
			record(variant, fixture.Kind+"-boundary", len(found), want, run)
			if fixture.Kind == "cache" && len(run.AuthorizationResults) > 0 && run.AuthorizationResults[0].CleanupStatus != "verified" {
				t.Error("framework cache reset not verified")
			}
		}
	}
	if len(rows) != 20 {
		t.Errorf("framework matrix incomplete: %d of 20 rows", len(rows))
	}
}

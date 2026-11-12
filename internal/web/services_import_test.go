package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func parseServicesRequest(t *testing.T, body, query string) (*httptest.ResponseRecorder, servicesImportResponse) {
	t.Helper()
	s := newTestServer(t, nil)
	rr := httptest.NewRecorder()
	s.handleServicesParse(rr, httptest.NewRequest(http.MethodPost, "/api/services/parse"+query, strings.NewReader(body)))
	var out servicesImportResponse
	if rr.Code == http.StatusOK {
		if rr.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("missing JSON content type")
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return rr, out
}

func TestServicesParseCSVSample(t *testing.T) {
	csv := "\xef\xbb\xbfname,url,image,repo\n" +
		"Auth Service,http://172.30.3.142:30862,hub.example.test/bcrs/bcrs-auth:6,\n" +
		"Common Service,http://172.30.3.10:31132;http://172.30.3.10:31133/api,hub.example.test/bcrs/bcrs_common_service:6,https://git.example.test/bcrs/common.git\n" +
		"\n" +
		"Client Portal,https://portal.example.test,,/src/client-portal\n"
	rr, out := parseServicesRequest(t, csv, "")
	if rr.Code != http.StatusOK || len(out.Errors) != 0 || len(out.Services) != 3 {
		t.Fatalf("status=%d out=%+v body=%s", rr.Code, out, rr.Body.String())
	}
	common := out.Services[1]
	if common.Name != "Common Service" || len(common.URLs) != 2 || common.Image == "" || common.Repo == "" {
		t.Fatalf("multi-URL row parsed wrong: %+v", common)
	}
	if out.Services[2].Repo != "/src/client-portal" || out.Services[2].Image != "" {
		t.Fatalf("optional columns parsed wrong: %+v", out.Services[2])
	}
}

func TestServicesParseCSVReportsBadRows(t *testing.T) {
	csv := "url,name,protected_path\n" +
		"ftp://bad,FTP,\n" +
		",Empty,\n" +
		"http://a.test,Dup,/api/me\n" +
		"http://b.test,dup,\n" +
		"http://c.test,NoSlash,api/me\n"
	rr, out := parseServicesRequest(t, csv, "?format=csv")
	if rr.Code != http.StatusOK || len(out.Services) != 1 || out.Services[0].ProtectedPath != "/api/me" {
		t.Fatalf("status=%d out=%+v", rr.Code, out)
	}
	if len(out.Errors) != 4 {
		t.Fatalf("expected 4 row errors, got %+v", out.Errors)
	}
	for _, want := range []string{"absolute http(s) URL", "at least one URL", "more than once", "must start with /"} {
		found := false
		for _, e := range out.Errors {
			found = found || strings.Contains(e.Message, want)
		}
		if !found {
			t.Errorf("missing error %q in %+v", want, out.Errors)
		}
	}
}

func TestServicesParseYAML(t *testing.T) {
	yamlBody := `services:
  - name: Auth Service
    url: http://172.30.3.142:30862
    image: hub.example.test/bcrs/bcrs-auth:6
    protected_path: /api/auth/me
  - name: Common Service
    urls: [http://172.30.3.10:31132, http://172.30.3.10:31133]
`
	rr, out := parseServicesRequest(t, yamlBody, "")
	if rr.Code != http.StatusOK || len(out.Errors) != 0 || len(out.Services) != 2 || len(out.Services[1].URLs) != 2 || out.Services[0].ProtectedPath != "/api/auth/me" {
		t.Fatalf("status=%d out=%+v", rr.Code, out)
	}
	list := "- name: Only\n  url: https://only.example.test\n"
	if _, out := parseServicesRequest(t, list, ""); len(out.Services) != 1 {
		t.Fatalf("bare YAML list not parsed: %+v", out)
	}
}

func TestServicesParseRejectsBadInput(t *testing.T) {
	if rr, _ := parseServicesRequest(t, "url,image\nhttp://a.test,x\n", "?format=csv"); rr.Code != http.StatusBadRequest {
		t.Fatalf("CSV without name column: %d", rr.Code)
	}
	if rr, _ := parseServicesRequest(t, "name,url\n", "?format=xml"); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown format: %d", rr.Code)
	}
	if rr, _ := parseServicesRequest(t, "  ", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d", rr.Code)
	}
	if rr, _ := parseServicesRequest(t, "name,url\n"+strings.Repeat("x", maxServicesImportBytes), ""); rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", rr.Code)
	}
	if rr, _ := parseServicesRequest(t, "name,image\nBad,-rf\n", ""); rr.Code != http.StatusOK {
		t.Fatalf("row-level error should not fail the request: %d", rr.Code)
	}
}

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/apifixture"
)

func TestAPIFixtureHandlersStoreAndRetrieveByFlatReference(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"id":"test","value":"sensitive body"}`
	upload := httptest.NewRecorder()
	s.handleAPIFixtures(upload, httptest.NewRequest(http.MethodPost, "/api/api-fixtures", strings.NewReader(body)))
	if upload.Code != http.StatusCreated {
		t.Fatalf("upload status=%d body=%s", upload.Code, upload.Body.String())
	}
	var meta apifixture.Metadata
	if err := json.Unmarshal(upload.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Ref == "" || meta.SizeBytes != len(body) {
		t.Fatalf("metadata=%+v", meta)
	}
	get := httptest.NewRecorder()
	s.handleAPIFixture(get, httptest.NewRequest(http.MethodGet, "/api/api-fixtures/"+meta.Ref, nil))
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), []byte(body)) || get.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download status=%d body=%s headers=%v", get.Code, get.Body.String(), get.Header())
	}
	if strings.Contains(upload.Body.String(), "sensitive body") {
		t.Fatal("upload response exposed fixture contents")
	}
}

func TestAPIFixtureUploadRejectsOversizeAndInvalidMethod(t *testing.T) {
	s := newTestServer(t, nil)
	large := httptest.NewRecorder()
	s.handleAPIFixtures(large, httptest.NewRequest(http.MethodPost, "/api/api-fixtures", strings.NewReader(strings.Repeat("x", apifixture.MaxBytes+1))))
	if large.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d body=%s", large.Code, large.Body.String())
	}
	method := httptest.NewRecorder()
	s.handleAPIFixtures(method, httptest.NewRequest(http.MethodGet, "/api/api-fixtures", nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method response status=%d allow=%q", method.Code, method.Header().Get("Allow"))
	}
}

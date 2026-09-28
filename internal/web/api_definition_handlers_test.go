package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIDefinitionUploadValidatesAndStoresImmutableSpec(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"openapi":"3.1.0","paths":{"/v1/users":{"get":{},"post":{}}}}`
	upload := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.handleAPIDefinitions(rr, httptest.NewRequest(http.MethodPost, "/api/api-definitions", strings.NewReader(body)))
		return rr
	}
	first := upload()
	second := upload()
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("upload status=%d/%d body=%s", first.Code, second.Code, first.Body.String())
	}
	var a, b apiDefinitionMetadata
	if err := json.Unmarshal(first.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || a.ID != b.ID || a.OperationCount != 2 || a.Format != "json" {
		t.Fatalf("metadata not stable/complete: %+v %+v", a, b)
	}
	stored, err := loadAPIDefinition(s.dataDir, a.ID)
	if err != nil || string(stored) != body {
		t.Fatalf("stored spec mismatch, err=%v", err)
	}
	info, err := os.Stat(filepath.Join(s.dataDir, "_api_definitions", a.ID+".spec"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("stored spec permissions=%v err=%v", info, err)
	}
}

func TestAPIDefinitionUploadRejectsRemoteRefsAndInvalidIDs(t *testing.T) {
	s := newTestServer(t, nil)
	body := "openapi: 3.1.0\npaths: {}\ncomponents:\n  schemas:\n    X:\n      $ref: https://outside.example/schema.yaml\n"
	rr := httptest.NewRecorder()
	s.handleAPIDefinitions(rr, httptest.NewRequest(http.MethodPost, "/api/api-definitions", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("remote ref status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := loadAPIDefinition(s.dataDir, "../../outside"); err == nil {
		t.Fatal("path-like definition ID accepted")
	}
}

func TestAPIDefinitionUploadEnforcesSizeLimit(t *testing.T) {
	s := newTestServer(t, nil)
	body := `{"openapi":"3.0.0","paths":{}}` + strings.Repeat(" ", 5<<20)
	rr := httptest.NewRecorder()
	s.handleAPIDefinitions(rr, httptest.NewRequest(http.MethodPost, "/api/api-definitions", strings.NewReader(body)))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

package scanner

import "testing"

func TestParseOpenAPIJSONAndRejectRemoteRefs(t *testing.T) {
	got, err := ParseOpenAPI([]byte(`{"openapi":"3.0.0","paths":{"/users":{"get":{},"post":{}},"/health":{"parameters":[]}}}`), "https://example.test")
	if err != nil || len(got) != 2 || got[0].Origin != "https://example.test" {
		t.Fatalf("got %#v err %v", got, err)
	}
	if _, err := ParseOpenAPI([]byte(`openapi: 3.0.0\npaths: {}\ncomponents:\n  schemas:\n    X:\n      $ref: http://evil.test/x`), "https://example.test"); err == nil {
		t.Fatal("remote ref accepted")
	}
}

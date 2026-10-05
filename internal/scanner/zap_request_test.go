package scanner

import (
	"strings"
	"testing"
)

func TestZAPRequestVariantsPreserveMethodAndEncodedBody(t *testing.T) {
	req := Request{InputRequests: []ScannerRequestInput{{EndpointID: "get", URL: "https://app.test/a%2Fb/?x=1&x=2", Method: "GET", Selected: true}, {EndpointID: "head", URL: "https://app.test/a%2Fb/?x=1&x=2", Method: "HEAD", Selected: true}}}
	if got := zapSelectedRequests(req); len(got) != 2 || got[1].EndpointID != "head" {
		t.Fatal(got)
	}
	message, err := zapRequestMessage(ScannerRequestInput{URL: "https://app.test/a%2Fb/?x=1&x=2", Method: "POST", ContentType: "application/json", Body: `{"id":"supplied"}`})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"POST https://app.test/a%2Fb/?x=1&x=2 HTTP/1.1", "Content-Type: application/json", "Content-Length: 17", `{"id":"supplied"}`} {
		if !strings.Contains(message, want) {
			t.Fatalf("%q missing from %q", want, message)
		}
	}
	if _, err := zapRequestMessage(ScannerRequestInput{URL: "https://app.test/", Method: "POST", ContentType: "application/json\r\nHost: attacker"}); err == nil {
		t.Fatal("accepted header injection")
	}
}

func TestURLOnlyAdaptersDoNotConvertHEADToGET(t *testing.T) {
	ep, _ := normalizeAttackSurfaceEndpoint("https://app.test/api?q=1", "HEAD", "fixture", "", 200, "application/json", []EndpointParameter{{Name: "q", Location: "query"}}, false, false)
	for _, name := range []string{"nuclei", "wapiti", "dalfox"} {
		if ok, reason := endpointEligibleForScanner(ep, name); ok || reason == "" {
			t.Fatalf("%s converted HEAD: %s", name, reason)
		}
	}
	if ok, reason := endpointEligibleForScanner(ep, "zap"); !ok {
		t.Fatalf("ZAP HEAD refused: %s", reason)
	}
}

func TestRequestIdentityRetainsEncodedQueryOrder(t *testing.T) {
	raw := "https://app.test/a%2Fb/?z=one%20two&a=1&z=three%2Ffour&a=2"
	ep, ok := normalizeAttackSurfaceEndpoint(raw, "GET", "fixture", "", 200, "", nil, false, false)
	if !ok || ep.URL != raw {
		t.Fatal(ep.URL, ok)
	}
	reordered, _ := normalizeAttackSurfaceEndpoint("https://app.test/a%2Fb/?a=1&a=2&z=one+two&z=three%2Ffour", "GET", "fixture", "", 200, "", nil, false, false)
	if ep.ID == reordered.ID || ep.GroupID != reordered.GroupID {
		t.Fatal("request identity confused with grouping identity")
	}
}

func TestTelemetryRetainsNonsecretEncodingAndRepeatedParameterPositions(t *testing.T) {
	raw := "https://app.test/a%2Fb/?z=one%20two&token=secret&a=1&z=three%2Ffour&a=2"
	got := SafeTelemetryURL(raw)
	if !strings.Contains(got, "z=one%20two&token=%5BREDACTED%5D&a=1&z=three%2Ffour&a=2") || strings.Contains(got, "token=secret") {
		t.Fatal(got)
	}
}

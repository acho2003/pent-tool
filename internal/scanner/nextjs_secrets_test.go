package scanner

import (
	"context"
	"net/http"

	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNextjsBundleAndNextDataSecretDetection(t *testing.T) {
	const awsKey = "AKIAIOSFODNN7EXAMPLE"
	const ghToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	const dbSecret = "p@ssw0rd-db-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/":
			// Landing page with __NEXT_DATA__ carrying a secret-named prop and
			// a populated serverRuntimeConfig, plus a script reference.
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body>` +
				`<script src="/app/_next/static/chunks/main.js"></script>` +
				`<script id="__NEXT_DATA__" type="application/json">` +
				`{"props":{"pageProps":{"user":"a","dbPassword":"` + dbSecret + `"}},"runtimeConfig":{"internalApi":"https://api.internal:9000"},"page":"/","buildId":"abc"}` +
				`</script></body></html>`))
		case "/app/_next/static/chunks/main.js":
			// A bundle leaking an AWS key, a GitHub token, a misused NEXT_PUBLIC_
			// secret var, and an internal URL.
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const a="` + awsKey + `";const g="` + ghToken + `";` +
				`const k=process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;` +
				`fetch("http://10.0.0.5:8080/admin");`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	req := nextjsTestRequest(t, server.URL+"/app/")
	req.Profile = ProfileNextjsDeep
	run := (nextjsAssetsRunner{}).Run(context.Background(), req, Config{}, nil)
	if run.Status != "completed" {
		t.Fatalf("run: %+v", run)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Finding{}
	for _, f := range findings {
		got[f.RuleID] = f
	}
	for _, rule := range []string{
		"nextjs-bundle-secret-aws-access-key",
		"nextjs-bundle-secret-github-pat",
		"nextjs-public-secret-var",
		"nextjs-internal-url",
		"nextjs-next-data-secret",
		"nextjs-server-runtime-config",
	} {
		if _, ok := got[rule]; !ok {
			t.Errorf("missing expected finding %s; got %v", rule, keysOf(got))
		}
	}
	if f := got["nextjs-bundle-secret-aws-access-key"]; f.Severity != "high" || f.CWE != "CWE-798" {
		t.Errorf("AWS finding wrong shape: %+v", f)
	}
	if f := got["nextjs-public-secret-var"]; !strings.Contains(f.Evidence, "NEXT_PUBLIC_STRIPE_SECRET_KEY") {
		t.Errorf("NEXT_PUBLIC finding should name the variable: %+v", f)
	}
	if f := got["nextjs-next-data-secret"]; !strings.Contains(f.Evidence, "dbPassword") {
		t.Errorf("__NEXT_DATA__ finding should name the key path: %+v", f)
	}
	// The detection must never copy a secret value into the saved artifact.
	data := findingsArtifactText(t, run)
	for _, secret := range []string{awsKey[4:], ghToken[4:], dbSecret} {
		if strings.Contains(data, secret) {
			t.Fatalf("a secret value leaked into the findings artifact: %q", secret)
		}
	}
}

func keysOf(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func findingsArtifactText(t *testing.T, run Run) string {
	t.Helper()
	if run.ArtifactPath == "" {
		return ""
	}
	data, err := os.ReadFile(run.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

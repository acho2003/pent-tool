package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCodeQLRuntimeAnalyzesBuildlessLanguages runs an operator-supplied CodeQL
// bundle (XALGORIX_CODEQL_PATH) on a small fixture with known dataflow defects.
// It proves the real CLI accepts the commands, needs no query download, and
// that its SARIF maps to located findings; a Go file must become a gap.
func TestCodeQLRuntimeAnalyzesBuildlessLanguages(t *testing.T) {
	path := os.Getenv("XALGORIX_CODEQL_PATH")
	if os.Getenv("XALGORIX_TEST_CODEQL") != "1" || path == "" {
		t.Skip("requires an operator-supplied CodeQL bundle")
	}
	source := writeSourceTree(t, map[string]string{
		"web/server.js": `const express = require("express");
const app = express();
app.get("/greet", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});
app.listen(3000);
`,
		"api/run.py": `import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)
`,
		"cmd/main.go": "package main\nfunc main() {}\n",
	})
	scanDir := t.TempDir()
	cfg := Config{CodeQLPath: path, CodeQLLicenseAccepted: true, CodeQLTimeout: 25 * time.Minute, MaxOutputBytes: 8 << 20}
	run := codeqlRunner{}.Run(context.Background(), Request{Target: source, ScanDir: scanDir, Scope: "source:fixture"}, cfg, nil)
	if run.Status != "completed" {
		t.Fatalf("status=%s reason=%s limitations=%+v", run.Status, run.Reason, run.Limitations)
	}
	findings, err := ParseRun(run)
	if err != nil {
		t.Fatal(err)
	}
	byLanguage := map[string]Finding{}
	for _, finding := range findings {
		switch {
		case strings.HasPrefix(finding.RuleID, "js/"):
			byLanguage["js"] = finding
		case strings.HasPrefix(finding.RuleID, "py/"):
			byLanguage["py"] = finding
		}
	}
	js, py := byLanguage["js"], byLanguage["py"]
	if js.RuleID == "" || !strings.HasPrefix(js.SourceLocation, "web/server.js:") || js.CWE == "" {
		t.Errorf("JavaScript reflected XSS was not reported with a location and CWE: %+v", findings)
	}
	if py.RuleID == "" || !strings.HasPrefix(py.SourceLocation, "api/run.py:") || py.CWE == "" {
		t.Errorf("Python command injection was not reported with a location and CWE: %+v", findings)
	}
	gapReported := false
	for _, limitation := range run.Limitations {
		if strings.Contains(limitation.Reason, "Go (1 files) needs a build toolchain") {
			gapReported = true
		}
	}
	if !gapReported || run.Completeness != "partial" {
		t.Errorf("the Go file must leave a visible gap: completeness=%s limitations=%+v", run.Completeness, run.Limitations)
	}
	if matches, _ := filepath.Glob(filepath.Join(scanDir, "scanner-output", "codeql", "db-*")); len(matches) != 0 {
		t.Errorf("databases must be removed after analysis: %v", matches)
	}
	t.Logf("CodeQL: %d findings; %s", len(findings), run.Reason)
	for _, finding := range findings {
		t.Logf("  %s %s %s %s", finding.Severity, finding.RuleID, finding.CWE, finding.SourceLocation)
	}
}

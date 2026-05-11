package reporting

import (
	"strings"
	"sync"
	"testing"
)

func TestCheckFalsePositive_MissingHeaders(t *testing.T) {
	tests := []struct {
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{"Missing X-Frame-Options Header", "The X-Frame-Options header is not set", "medium", "", true},
		{"Missing Content-Security-Policy", "CSP is not configured", "high", "", true},
		{"Missing HSTS Header", "Strict-Transport-Security not found", "critical", "", true},
		// Low/info severity should NOT be rejected for headers
		{"Missing X-Frame-Options Header", "Header not set", "info", "", false},
		{"Missing X-Frame-Options Header", "Header not set", "low", "", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.severity, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_VersionDisclosure(t *testing.T) {
	tests := []struct {
		title      string
		severity   string
		wantReject bool
	}{
		{"Server Version Disclosure - Apache 2.4.41", "medium", true},
		{"X-Powered-By Header Reveals Technology", "high", true},
		{"Technology Disclosure via banner", "critical", true},
		{"Server Version Disclosure", "info", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.title, tt.severity, "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v", tt.title, tt.severity, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_SSL(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Weak SSL Cipher Suite", true},
		{"TLS 1.0 Enabled", true},
		{"Expired Certificate", true},
		{"POODLE Vulnerability", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "medium", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v", tt.title, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_DNS(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Missing SPF Record", true},
		{"No DMARC Policy", true},
		{"DKIM Not Configured", true},
		{"Email Spoofing Possible via missing SPF", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "high", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_CORSWithoutProof(t *testing.T) {
	// CORS without cookie/token theft proof → rejected at medium+
	result := checkFalsePositive("CORS Misconfiguration", "Access-Control-Allow-Origin reflects input", "high", "curl showed reflected origin")
	if result == "" {
		t.Error("CORS without exploit proof should be rejected at high severity")
	}

	// CORS WITH theft proof → accepted
	result = checkFalsePositive("CORS Misconfiguration", "Allows credential theft", "high", "JavaScript fetch() exfiltrates session cookie via CORS")
	if result != "" {
		t.Errorf("CORS with exploit proof should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_OpenRedirectWithoutChain(t *testing.T) {
	// Open redirect alone → rejected at medium+
	result := checkFalsePositive("Open Redirect", "Redirects to attacker URL", "medium", "curl -L shows redirect to evil.com")
	if result == "" {
		t.Error("open redirect without chain should be rejected at medium+")
	}

	// Open redirect chained with OAuth → accepted
	result = checkFalsePositive("Open Redirect to OAuth Token Theft", "Redirect steals OAuth token", "high", "OAuth code redirected via open redirect, token stolen via phishing")
	if result != "" {
		t.Errorf("open redirect with OAuth chain should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_CSVInjection(t *testing.T) {
	result := checkFalsePositive("CSV Injection in Export", "Formula injection in CSV export", "medium", "")
	if result == "" {
		t.Error("CSV injection at medium should be rejected")
	}

	result = checkFalsePositive("CSV Injection in Export", "Formula injection", "low", "")
	if result != "" {
		t.Errorf("CSV injection at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_Clickjacking(t *testing.T) {
	result := checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "high", "")
	if result == "" {
		t.Error("clickjacking at high should be rejected")
	}

	result = checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "low", "")
	if result != "" {
		t.Errorf("clickjacking at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_DirectoryListing(t *testing.T) {
	// Directory listing without sensitive files → rejected
	result := checkFalsePositive("Directory Listing Enabled", "Apache autoindex enabled", "medium", "Shows index of /images/")
	if result == "" {
		t.Error("directory listing without sensitive files should be rejected at medium+")
	}

	// Directory listing WITH sensitive files → accepted
	result = checkFalsePositive("Directory Listing Enabled", "Directory listing exposes backup files", "high", "Found database.sql backup with password hashes")
	if result != "" {
		t.Errorf("directory listing with sensitive files should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_TraceMethod(t *testing.T) {
	result := checkFalsePositive("TRACE Method Enabled", "HTTP TRACE method is enabled", "medium", "")
	if result == "" {
		t.Error("TRACE method should be rejected")
	}

	result = checkFalsePositive("OPTIONS Method Enabled", "HTTP OPTIONS reveals methods", "low", "")
	if result == "" {
		t.Error("OPTIONS method should be rejected")
	}
}

func TestCheckFalsePositive_ScannerOnly(t *testing.T) {
	result := checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found potential SQLi", "high", "")
	if result == "" {
		t.Error("scanner-only finding without proof should be rejected")
	}

	result = checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found SQLi, manually verified", "high", "sqlmap confirmed with --dump")
	if result != "" {
		t.Errorf("scanner finding with manual proof should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_RealVulns(t *testing.T) {
	// Real vulnerabilities should NOT be rejected
	realVulns := []struct {
		title    string
		desc     string
		severity string
		proof    string
	}{
		{"SQL Injection in login endpoint", "Union-based SQLi", "critical", "sqlmap extracted admin table"},
		{"Stored XSS in comment field", "Script tag stored", "high", "alert(1) reflected in response body"},
		{"SSRF via image URL parameter", "Internal metadata accessed", "critical", "169.254.169.254 metadata returned"},
		{"IDOR in user profile API", "Can access other users", "high", "Changed user_id=1 to user_id=2, got admin data"},
		{"Remote Code Execution via file upload", "PHP shell uploaded", "critical", "whoami returned www-data"},
	}

	for _, tt := range realVulns {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		if result != "" {
			t.Errorf("real vuln %q should NOT be rejected, got: %s", tt.title, result)
		}
	}
}

func TestReportVulnChecksDuplicateBeforeAppending(t *testing.T) {
	contextID := "test-report-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	args := validReportArgs()
	first, err := reportVulnWithContextID(contextID, args)
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	duplicateArgs := validReportArgs()
	duplicateArgs["endpoint"] = "https://example.com/login?id=2"
	second, err := reportVulnWithContextID(contextID, duplicateArgs)
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if !strings.Contains(second.Output, "DUPLICATE") {
		t.Fatalf("second report output = %q, want duplicate", second.Output)
	}
	if got, ok := second.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnConcurrentDuplicatesOnlyAppendOnce(t *testing.T) {
	contextID := "test-report-concurrent-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	const attempts = 20
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, _ = reportVulnWithContextID(contextID, validReportArgs())
		}()
	}
	wg.Wait()

	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities after concurrent duplicates = %d, want 1", got)
	}
}

func validReportArgs() map[string]string {
	return map[string]string{
		"title":               "SQL Injection in Login Endpoint",
		"severity":            "high",
		"description":         "Union-based SQL injection allows extraction of user records from the login endpoint.",
		"exploitation_proof":  "sql injection data extraction confirmed; dumped user data including email address records from database",
		"verification_method": "data_extracted",
		"impact":              "Unauthorized attackers can extract sensitive user data.",
		"target":              "https://example.com",
		"endpoint":            "https://example.com/login?id=1",
		"method":              "GET",
		"cvss":                "7.5",
		"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	}
}

func TestHasStrongEvidence(t *testing.T) {
	tests := []struct {
		severity string
		proof    string
		desc     string
		want     bool
	}{
		{"critical", "rce: executed whoami, got root", "", true},
		{"critical", "", "", false},
		{"high", "sqli with data extraction", "", true},
		{"high", "found a parameter", "", false},
		{"medium", "reflected input in response", "", true},
		{"low", "anything goes", "", true}, // low/info don't need strong evidence
		{"info", "anything", "", true},
	}

	for _, tt := range tests {
		got := hasStrongEvidence(tt.severity, tt.proof, tt.desc)
		if got != tt.want {
			t.Errorf("severity=%q proof=%q: want=%v got=%v", tt.severity, tt.proof[:min(len(tt.proof), 30)], tt.want, got)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

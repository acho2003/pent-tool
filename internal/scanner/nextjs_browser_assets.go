package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Inspect only bytes already returned to the authenticated same-origin browser.
// This helper performs no fetches and never persists response bodies or keys.
func nextjsAuthenticatedAsset(req Request, raw string, status int, contentType string, body []byte, sameOrigin bool, evidence string) (*Finding, error) {
	if req.Profile != ProfileNextjsDeep || req.TargetAuth == "" || req.BrowserAccessTest || !sameOrigin || status < 200 || status >= 300 {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, nil
	}
	javascript := strings.HasSuffix(parsed.Path, ".js") || strings.Contains(contentType, "javascript")
	sourceMap := strings.HasSuffix(parsed.Path, ".map")
	if !javascript && !sourceMap {
		return nil, nil
	}
	var finding *Finding
	var gap error
	if sourceMap {
		var sources []nextjsMapSource
		sources, gap = nextjsSourceMapContents(body)
		for _, source := range sources {
			if candidate := nextjsPrivateKeyFinding(req, raw, []byte(source.Content), evidence); candidate != nil {
				finding = candidate
				break
			}
		}
	} else {
		finding = nextjsPrivateKeyFinding(req, raw, body, evidence)
	}
	if finding != nil {
		finding.Scanner = "browser"
		finding.RuleID = "nextjs-authenticated-private-key"
		finding.SourceID = nextjsSourceID(finding.RuleID, raw+"\x00"+req.AuthContextID)
		finding.Title = "Private key material delivered in an authenticated client asset"
		finding.Target = SafeTelemetryURL(req.Target)
		finding.Scope = req.Scope
		finding.Description = "A same-origin response delivered to the verified browser identity contains a structurally valid unencrypted private key. This proves client delivery for that identity; key ownership and privileges were not tested."
	}
	return finding, gap
}

func parseBrowserAssetFindings(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	var findings []Finding
	rows := 0
	for scanner.Scan() {
		rows++
		if rows > 20000 {
			return findings, fmt.Errorf("browser artifact record limit exceeded")
		}
		var row struct {
			Finding *Finding `json:"finding"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil {
			return findings, fmt.Errorf("browser observation JSON invalid")
		}
		if row.Finding == nil {
			continue
		}
		if row.Finding.Scanner != "browser" || row.Finding.RuleID != "nextjs-authenticated-private-key" || row.Finding.Confidence != "confirmed" {
			return findings, fmt.Errorf("unsupported browser finding record")
		}
		if len(findings) >= 500 {
			return findings, fmt.Errorf("browser finding limit exceeded")
		}
		findings = append(findings, *row.Finding)
	}
	return findings, scanner.Err()
}

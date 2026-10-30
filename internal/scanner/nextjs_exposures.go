package scanner

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"regexp"
	"strings"
)

var nextjsPrivateKeyPEM = regexp.MustCompile(`-----BEGIN (?:RSA |EC |)PRIVATE KEY-----[A-Za-z0-9+/=\r\n\t ]+-----END (?:RSA |EC |)PRIVATE KEY-----`)

// Confirm key structure locally. Values, excerpts and key-derived fingerprints
// never enter findings or artifacts, and discovered credentials are never used.
func nextjsPrivateKeyFinding(req Request, endpoint string, body []byte, evidenceRef string) *Finding {
	decoded := strings.ReplaceAll(string(body), `\n`, "\n")
	decoded = strings.ReplaceAll(decoded, `\r`, "\r")
	for _, encoded := range nextjsPrivateKeyPEM.FindAllString(decoded, 10) {
		if len(encoded) > 16384 {
			continue
		}
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			continue
		}
		valid := false
		switch block.Type {
		case "PRIVATE KEY":
			_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			valid = err == nil
		case "RSA PRIVATE KEY":
			_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			valid = err == nil
		case "EC PRIVATE KEY":
			_, err := x509.ParseECPrivateKey(block.Bytes)
			valid = err == nil
		}
		if !valid {
			continue
		}
		return &Finding{SourceID: nextjsSourceID("nextjs-public-private-key", endpoint), Scanner: "nextjs-assets", RuleID: "nextjs-public-private-key", Title: "Private key material in a public client response", Severity: "high", Target: req.Target, Endpoint: SafeTelemetryURL(endpoint), Method: http.MethodGet, CWE: "CWE-200", Confidence: "confirmed", Description: "An anonymous response contains a structurally valid unencrypted private key. Key ownership and privileges were not tested.", Evidence: "A PEM private key was parsed locally from the response; key bytes and source excerpts were not retained.", EvidenceRef: evidenceRef, Remediation: "Remove private key material from client assets and serialized page data. Determine whether the key is in use and rotate affected credentials."}
	}
	return nil
}

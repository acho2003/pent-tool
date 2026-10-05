package web

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanner"
)

const maxFindingEvidenceRunes = 2000

var (
	evidenceSecretField = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|session(?:id)?|csrf|email|phone|mobile)(["']?\s*[:=]\s*["']?)([^"'& ,;\t\r\n}\]]+)`)
	evidenceCookieLine  = regexp.MustCompile(`(?im)^(set-cookie|cookie)\s*:\s*[^\r\n]*`)
	evidenceBearer      = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
	evidenceURL         = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

func sanitizeEvidenceURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	q := u.Query()
	for key := range q {
		if sensitiveEvidenceKey(key) {
			q.Set(key, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()
	return strings.ReplaceAll(u.String(), "%5BREDACTED%5D", "[REDACTED]")
}

func sensitiveEvidenceKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
	for _, marker := range []string{"password", "passwd", "pass", "token", "secret", "apikey", "authorization", "auth", "session", "csrf", "cookie", "email", "phone", "mobile", "signature", "credential", "privatekey", "clientsecret", "otp"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

func sanitizeEvidenceText(raw string) string {
	if raw == "" {
		return ""
	}
	clean := evidenceCookieLine.ReplaceAllString(raw, "$1: [REDACTED]")
	clean = evidenceBearer.ReplaceAllString(clean, "$1 [REDACTED]")
	clean = evidenceSecretField.ReplaceAllString(clean, "$1$2[REDACTED]")
	clean = evidenceURL.ReplaceAllStringFunc(clean, sanitizeEvidenceURL)
	runes := []rune(clean)
	if len(runes) > maxFindingEvidenceRunes {
		clean = string(runes[:maxFindingEvidenceRunes]) + "… [truncated]"
	}
	return clean
}

func sanitizeFindingObservation(o scanner.RawObservation) scanner.RawObservation {
	o.SourceID = sanitizeEvidenceText(o.SourceID)
	o.Target = sanitizeEvidenceText(sanitizeEvidenceURL(o.Target))
	o.Endpoint = sanitizeEvidenceURL(o.Endpoint)
	o.CanonicalEndpoint = sanitizeEvidenceURL(o.CanonicalEndpoint)
	o.Description = sanitizeEvidenceText(o.Description)
	o.Evidence = sanitizeEvidenceText(o.Evidence)
	o.Remediation = sanitizeEvidenceText(o.Remediation)
	o.Package = sanitizeEvidenceText(o.Package)
	o.PackageVersion = sanitizeEvidenceText(o.PackageVersion)
	o.SourceLocation = sanitizeEvidenceText(o.SourceLocation)
	o.Container = sanitizeEvidenceText(o.Container)
	o.Resource = sanitizeEvidenceText(o.Resource)
	o.Parameter = sanitizeEvidenceText(o.Parameter)
	o.EvidenceReference = sanitizeEvidenceText(o.EvidenceReference)
	return o
}

func sanitizeSecurityFinding(f scanner.SecurityFinding) scanner.SecurityFinding {
	f.Target = sanitizeEvidenceText(sanitizeEvidenceURL(f.Target))
	f.Endpoints = append([]scanner.FindingEndpoint(nil), f.Endpoints...)
	for i := range f.Endpoints {
		f.Endpoints[i].Endpoint = sanitizeEvidenceURL(f.Endpoints[i].Endpoint)
		f.Endpoints[i].CanonicalEndpoint = sanitizeEvidenceURL(f.Endpoints[i].CanonicalEndpoint)
		f.Endpoints[i].Parameter = sanitizeEvidenceText(f.Endpoints[i].Parameter)
	}
	return f
}

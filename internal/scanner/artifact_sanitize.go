package scanner

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

var artifactBearer = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
var artifactHeader = regexp.MustCompile(`(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*[^\r\n]*`)

// The key may itself be quoted (a JSON document embedded in a string value), so
// an optional quote is allowed before the delimiter and before the value.
var artifactAssignment = regexp.MustCompile(`(?i)\b(password|passwd|access_token|refresh_token|id_token|auth_token|api_key|apikey|client_secret|secret|token|session_id|sessionid|session|csrf_token)["']?\s*[:=]\s*["']?[^\s&,;"'<>]+`)
var artifactURL = regexp.MustCompile(`https?://[^\s"'<>]+`)

func sanitizeArtifactText(raw string, secrets []string) string {
	clean := redact(raw, secrets)
	clean = artifactHeader.ReplaceAllString(clean, "$1: [REDACTED]")
	clean = artifactBearer.ReplaceAllString(clean, "$1 [REDACTED]")
	clean = artifactAssignment.ReplaceAllString(clean, "$1=[REDACTED]")
	return artifactURL.ReplaceAllStringFunc(clean, SafeTelemetryURL)
}

func sanitizeArtifactValue(value any, secrets []string) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if sensitiveArtifactKey(key) {
				v[key] = "[REDACTED]"
			} else {
				v[key] = sanitizeArtifactValue(item, secrets)
			}
		}
	case []any:
		for i := range v {
			v[i] = sanitizeArtifactValue(v[i], secrets)
		}
	case string:
		return sanitizeArtifactText(v, secrets)
	}
	return value
}

// Decode native formats before replacing values: escaped headers and quoted
// secrets must never turn valid scanner records into malformed JSON or XML.
func sanitizeArtifactData(path string, data []byte, secrets []string) ([]byte, error) {
	extension := strings.ToLower(filepath.Ext(path))
	if extension == ".json" || extension == ".jsonl" || extension == ".ndjson" {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		count := 0
		for {
			var value any
			err := decoder.Decode(&value)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("sanitize scanner JSON: %w", err)
			}
			count++
			if extension == ".json" && count > 1 {
				return nil, fmt.Errorf("multiple records in JSON artifact")
			}
			if err := encoder.Encode(sanitizeArtifactValue(value, secrets)); err != nil {
				return nil, err
			}
		}
		if count == 0 && extension == ".json" {
			return nil, fmt.Errorf("empty scanner JSON artifact")
		}
		return out.Bytes(), nil
	}
	if extension == ".xml" {
		decoder := xml.NewDecoder(bytes.NewReader(data))
		var out bytes.Buffer
		encoder := xml.NewEncoder(&out)
		var sensitive []bool
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("sanitize scanner XML: %w", err)
			}
			switch v := token.(type) {
			case xml.StartElement:
				parent := len(sensitive) > 0 && sensitive[len(sensitive)-1]
				sensitive = append(sensitive, parent || sensitiveArtifactKey(v.Name.Local))
				for i := range v.Attr {
					if sensitiveArtifactKey(v.Attr[i].Name.Local) {
						v.Attr[i].Value = "[REDACTED]"
					} else {
						v.Attr[i].Value = sanitizeArtifactText(v.Attr[i].Value, secrets)
					}
				}
				token = v
			case xml.EndElement:
				if len(sensitive) > 0 {
					sensitive = sensitive[:len(sensitive)-1]
				}
			case xml.CharData:
				clean := sanitizeArtifactText(string(v), secrets)
				if len(sensitive) > 0 && sensitive[len(sensitive)-1] {
					clean = "[REDACTED]"
				}
				token = xml.CharData(clean)
			case xml.Comment:
				token = xml.Comment(sanitizeArtifactText(string(v), secrets))
			}
			if err := encoder.EncodeToken(token); err != nil {
				return nil, err
			}
		}
		if err := encoder.Flush(); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	return []byte(sanitizeArtifactText(string(data), secrets)), nil
}

// Match credential field names rather than broad substrings such as "key":
// scanner metadata (template keys, token counts, session IDs) stays typed.
func sensitiveArtifactKey(name string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(name))
	switch normalized {
	case "authorization", "proxyauthorization", "cookie", "setcookie", "xapikey", "apikey", "password", "passwd", "pwd", "secret", "clientsecret", "accesstoken", "refreshtoken", "idtoken", "token", "csrftoken", "privatekey", "credentials", "sessioncookie":
		return true
	}
	return false
}

package scanner

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Compare decoded text and attribute values without executing scripts or joining
// separate nodes. The tokenizer preserves raw-text semantics for script/style.
func nextjsHTMLMarker(body []byte, marker string) (bool, error) {
	if len(body) > 64<<10 || !utf8.Valid(body) {
		return false, fmt.Errorf("HTML response exceeds supported text bounds")
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	tokenizer.SetMaxBuf(64 << 10)
	found := false
	for tokens := 0; ; tokens++ {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if tokenizer.Err() != io.EOF || len(tokenizer.Raw()) > 0 {
				return false, fmt.Errorf("HTML resource response is incomplete or unsupported")
			}
			return found, nil
		}
		if tokens >= 8192 {
			return false, fmt.Errorf("HTML resource token count exceeds comparison limit")
		}
		token := tokenizer.Token()
		switch kind {
		case html.TextToken:
			found = found || strings.Contains(token.Data, marker)
		case html.StartTagToken, html.SelfClosingTagToken:
			if len(token.Attr) > 1024 {
				return false, fmt.Errorf("HTML resource attribute count exceeds comparison limit")
			}
			for _, attribute := range token.Attr {
				found = found || strings.Contains(attribute.Val, marker)
			}
		}
	}
}

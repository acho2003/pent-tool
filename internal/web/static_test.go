package web

import (
	"strings"
	"testing"
)

func TestStaticApp_ModelSuggestionsStayCurrentAndEditable(t *testing.T) {
	data, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	app := string(data)

	for _, want := range []string{
		"gemini-3.1-pro-preview",
		"gemini-3.1-pro-preview-customtools",
		"gemini-3.1-flash-lite-preview",
		"deepseek-v4-pro",
		"deepseek-v4-flash",
		"configureModelInput",
		"Model name (type custom ID or pick a suggestion)",
	} {
		if !strings.Contains(app, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}

	if strings.Contains(app, "'gemini-3-pro-preview', 'gemini-3-flash-preview'") {
		t.Fatal("Gemini suggestions still prioritize the deprecated Gemini 3 Pro Preview entry")
	}
}

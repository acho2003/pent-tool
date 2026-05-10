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

func TestStaticApp_ChatRemainsAvailableAfterCompletion(t *testing.T) {
	data, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	app := string(data)

	for _, want := range []string{
		"showChatInput('Ask follow-up questions about this completed scan')",
		"payload.instance_id = instanceID",
		"if (!isReplay && evt.agent_id && !currentInstanceID)",
		"renderPhaseTimeline(currentScanPhases, currentPhase, currentScanStatus)",
		"Start Saved Scan",
	} {
		if !strings.Contains(app, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}

	if strings.Contains(app, "case 'queue_finished':\n                scanRunning = false;\n                setStatus('finished', 'COMPLETED');\n                toggleButtons(false);\n                hideQueueBar();\n                hideChatInput();") {
		t.Fatal("queue completion still hides the chat input")
	}
}

func TestStaticApp_ReplayDoesNotTriggerLifecycleSideEffects(t *testing.T) {
	data, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	app := string(data)

	for _, want := range []string{
		"const isReplay = replay === true;",
		"if (evt.current_phase && !isReplay)",
		"if (!isReplay) showToast('🚀 Scan started', 'info');",
		"if (!isReplay && !currentInstanceID)",
		"Agent \"finished\" events are session-level",
		"if (currentView === 'scan' && currentInstanceID)",
		"const inst = await resp.json();",
		"if (currentView === 'dashboard')",
		"refreshInstances();",
	} {
		if !strings.Contains(app, want) {
			t.Fatalf("app.js missing replay/state guard %q", want)
		}
	}
}

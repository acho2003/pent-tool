package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJournalIntentPersistedBeforeSend(t *testing.T) {
	scanDir := t.TempDir()
	journal, err := OpenWriteJournal(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := WriteJournalPath(scanDir); got != filepath.Join(scanDir, "workflow", "write-journal-v1.json") {
		t.Fatalf("path = %q", got)
	}
	err = journal.RecordIntent(WriteJournalEntry{OperationID: "op-1", JobID: "writes", Method: "post",
		RedactedURL: "https://user:pw@app.test/api/items?token=secret#frag", FixtureRef: "fixture:item", CleanupRef: "cleanup:item"})
	if err != nil {
		t.Fatal(err)
	}
	// The intent is on disk before the caller sends anything: a crash right
	// here must leave a record a fresh process sees as unresolved.
	info, err := os.Stat(WriteJournalPath(scanDir))
	if err != nil {
		t.Fatalf("intent not persisted: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(WriteJournalPath(scanDir))
	for _, secret := range []string{"secret", "pw@", "frag"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("journal leaks %q: %s", secret, data)
		}
	}
	entries, err := LoadWriteJournal(scanDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	e := entries[0]
	if e.State != WriteStateIntent || e.IntentAt == "" || e.SentAt != "" || e.Method != "POST" || e.RedactedURL != "https://app.test/api/items" {
		t.Fatalf("intent entry = %+v", e)
	}

	// An operation is journaled exactly once; a second intent is a replay.
	if err := journal.RecordIntent(WriteJournalEntry{OperationID: "op-1", Method: "POST", RedactedURL: "https://app.test/api/items"}); !errors.Is(err, ErrWriteAlreadyJournaled) {
		t.Fatalf("duplicate intent err = %v", err)
	}
	if err := journal.RecordIntent(WriteJournalEntry{Method: "POST"}); err == nil {
		t.Fatal("intent without operation id accepted")
	}
	if err := journal.MarkSent("missing"); err == nil {
		t.Fatal("sent recorded for unknown operation")
	}
	if err := journal.MarkCleanup("op-1", true); err == nil {
		t.Fatal("cleanup recorded before send")
	}

	if err := journal.MarkSent("op-1"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWriteJournal(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Entries()
	if len(got) != 1 || got[0].State != WriteStateSent || got[0].SentAt == "" || got[0].IntentAt != e.IntentAt {
		t.Fatalf("sent entry = %+v", got)
	}
	if err := reopened.MarkSent("op-1"); err == nil {
		t.Fatal("operation marked sent twice")
	}
	if err := reopened.MarkCleanup("op-1", true); err != nil {
		t.Fatal(err)
	}
	if entries, _ := LoadWriteJournal(scanDir); entries[0].State != WriteStateCleanupDone || entries[0].CleanupAt == "" {
		t.Fatalf("cleanup entry = %+v", entries[0])
	}
	dirEntries, _ := os.ReadDir(filepath.Dir(WriteJournalPath(scanDir)))
	if len(dirEntries) != 1 {
		t.Fatalf("stray journal files: %v", dirEntries)
	}
}

func TestWriteJournalUnresolvedIntentReported(t *testing.T) {
	scanDir := t.TempDir()
	if got, err := UnresolvedWrites(scanDir); err != nil || len(got) != 0 {
		t.Fatalf("no journal: %v, %v", got, err)
	}
	journal, err := OpenWriteJournal(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []WriteJournalEntry{
		{OperationID: "intent-only", JobID: "job-a", Method: "POST", RedactedURL: "https://app.test/a"},
		{OperationID: "sent-no-cleanup", JobID: "job-a", Method: "PUT", RedactedURL: "https://app.test/b"},
		{OperationID: "sent-cleanup-pending", JobID: "job-b", Method: "POST", RedactedURL: "https://app.test/c", CleanupRef: "cleanup:c"},
		{OperationID: "cleanup-done", JobID: "job-b", Method: "POST", RedactedURL: "https://app.test/d", CleanupRef: "cleanup:d"},
		{OperationID: "cleanup-failed", JobID: "job-c", Method: "DELETE", RedactedURL: "https://app.test/e", CleanupRef: "cleanup:e"},
	} {
		if err := journal.RecordIntent(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sent-no-cleanup", "sent-cleanup-pending", "cleanup-done", "cleanup-failed"} {
		if err := journal.MarkSent(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.MarkCleanup("cleanup-done", true); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkCleanup("cleanup-failed", false); err != nil {
		t.Fatal(err)
	}

	unresolved, err := UnresolvedWrites(scanDir)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]WriteJournalEntry{}
	for _, e := range unresolved {
		ids[e.OperationID] = e
	}
	if len(ids) != 2 || ids["intent-only"].State != WriteStateIntent || ids["sent-cleanup-pending"].State != WriteStateSent {
		t.Fatalf("unresolved = %+v", unresolved)
	}
	if ids["intent-only"].JobID != "job-a" || ids["sent-cleanup-pending"].JobID != "job-b" {
		t.Fatalf("unresolved entries lost their job ids: %+v", unresolved)
	}
	entries, _ := LoadWriteJournal(scanDir)
	for _, e := range entries {
		if e.OperationID == "cleanup-failed" && (e.State != WriteStateCleanupFailed || e.CleanupAt == "") {
			t.Fatalf("cleanup failure not recorded: %+v", e)
		}
	}
}

func TestWriteJournalCorruptFileTreatedAsUnresolvedNotEmpty(t *testing.T) {
	for name, body := range map[string]string{
		"truncated":      `{"schema_version":1,"entries":[{"operation_id":"op-1","state":"int`,
		"garbage":        "not json",
		"unknown schema": `{"schema_version":2,"entries":[]}`,
		"no schema":      `{"entries":[]}`,
		"empty file":     "",
	} {
		t.Run(name, func(t *testing.T) {
			scanDir := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(WriteJournalPath(scanDir)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(WriteJournalPath(scanDir), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			unresolved, err := UnresolvedWrites(scanDir)
			if !errors.Is(err, ErrWriteJournalCorrupt) {
				t.Fatalf("err = %v", err)
			}
			if len(unresolved) == 0 {
				t.Fatal("corrupt journal reported as having nothing unresolved")
			}
			if _, err := LoadWriteJournal(scanDir); !errors.Is(err, ErrWriteJournalCorrupt) {
				t.Fatalf("load err = %v", err)
			}
			// No further writes may be journaled (and so sent) on top of an
			// unreadable journal, and the evidence is not overwritten.
			if _, err := OpenWriteJournal(scanDir); !errors.Is(err, ErrWriteJournalCorrupt) {
				t.Fatalf("open err = %v", err)
			}
			if data, _ := os.ReadFile(WriteJournalPath(scanDir)); string(data) != body {
				t.Fatalf("corrupt journal was rewritten: %q", data)
			}
		})
	}
}

package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// WriteJournalSchemaVersion is the only journal schema this build understands.
const WriteJournalSchemaVersion = 1

// WriteState is the last persisted transition of a journaled write.
type WriteState string

const (
	// WriteStateIntent: the write is about to be sent; it may or may not have
	// reached the target.
	WriteStateIntent WriteState = "intent"
	// WriteStateSent: the target answered the write.
	WriteStateSent WriteState = "sent"
	// WriteStateCleanupDone / WriteStateCleanupFailed: the declared cleanup ran.
	WriteStateCleanupDone   WriteState = "cleanup_done"
	WriteStateCleanupFailed WriteState = "cleanup_failed"
)

var (
	// ErrWriteJournalCorrupt means the journal exists but cannot be trusted.
	// Its writes must be treated as unresolved, never as absent.
	ErrWriteJournalCorrupt = errors.New("write journal is unreadable or has an unknown schema")
	// ErrWriteAlreadyJournaled means the operation already has an intent; a
	// second one would be a replay.
	ErrWriteAlreadyJournaled = errors.New("write operation is already journaled")
)

// WriteJournalEntry is one approved state-changing operation. RedactedURL never
// carries userinfo, query or fragment; FixtureRef and CleanupRef name stored
// fixtures, never their contents.
type WriteJournalEntry struct {
	OperationID string     `json:"operation_id"`
	JobID       string     `json:"job_id,omitempty"`
	Method      string     `json:"method"`
	RedactedURL string     `json:"redacted_url"`
	FixtureRef  string     `json:"fixture_ref,omitempty"`
	CleanupRef  string     `json:"cleanup_ref,omitempty"`
	State       WriteState `json:"state"`
	IntentAt    string     `json:"intent_at,omitempty"`
	SentAt      string     `json:"sent_at,omitempty"`
	CleanupAt   string     `json:"cleanup_at,omitempty"`
}

// Unresolved reports whether the entry's outcome is unknown: an intent with no
// sent record (the request may have reached the target), or a sent write whose
// declared cleanup has no outcome yet.
func (e WriteJournalEntry) Unresolved() bool {
	switch e.State {
	case WriteStateSent:
		return e.CleanupRef != ""
	case WriteStateCleanupDone, WriteStateCleanupFailed:
		return false
	default:
		return true
	}
}

type writeJournalFile struct {
	SchemaVersion int                 `json:"schema_version"`
	Entries       []WriteJournalEntry `json:"entries"`
}

// WriteJournal is the gate for state-changing requests: every transition is
// persisted atomically before the caller proceeds, so an interrupted write is
// visible to a later process and is never replayed automatically.
type WriteJournal struct {
	mu      sync.Mutex
	path    string
	entries []WriteJournalEntry
}

// WriteJournalPath is <scanDir>/workflow/write-journal-v1.json.
func WriteJournalPath(scanDir string) string {
	return filepath.Join(scanDir, "workflow", "write-journal-v1.json")
}

// OpenWriteJournal loads the scan's journal (empty when none exists). A
// corrupt or unknown-schema journal returns ErrWriteJournalCorrupt and is left
// untouched, so no new write can be journaled on top of lost evidence.
func OpenWriteJournal(scanDir string) (*WriteJournal, error) {
	entries, err := LoadWriteJournal(scanDir)
	if err != nil {
		return nil, err
	}
	return &WriteJournal{path: WriteJournalPath(scanDir), entries: entries}, nil
}

// LoadWriteJournal returns the persisted entries. A missing journal is empty;
// any other read, parse or schema failure is ErrWriteJournalCorrupt.
func LoadWriteJournal(scanDir string) ([]WriteJournalEntry, error) {
	data, err := os.ReadFile(WriteJournalPath(scanDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWriteJournalCorrupt, err)
	}
	var file writeJournalFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWriteJournalCorrupt, err)
	}
	if file.SchemaVersion != WriteJournalSchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %d", ErrWriteJournalCorrupt, file.SchemaVersion)
	}
	return file.Entries, nil
}

// UnresolvedWrites returns the scan's entries whose outcome is unknown. A
// corrupt journal is unresolved, not empty: it returns a single placeholder
// entry together with ErrWriteJournalCorrupt, so callers that only check the
// length still refuse to re-run.
func UnresolvedWrites(scanDir string) ([]WriteJournalEntry, error) {
	entries, err := LoadWriteJournal(scanDir)
	if err != nil {
		return []WriteJournalEntry{{OperationID: "unreadable-write-journal", State: WriteStateIntent}}, err
	}
	var out []WriteJournalEntry
	for _, e := range entries {
		if e.Unresolved() {
			out = append(out, e)
		}
	}
	return out, nil
}

// Entries returns a copy of the journal's entries.
func (j *WriteJournal) Entries() []WriteJournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Clone(j.entries)
}

// RecordIntent persists an intent for a write that has not been sent yet. The
// caller must not send the write unless RecordIntent returned nil. An
// operation ID can be journaled only once.
func (j *WriteJournal) RecordIntent(entry WriteJournalEntry) error {
	if strings.TrimSpace(entry.OperationID) == "" {
		return fmt.Errorf("write journal: operation id is required")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.indexLocked(entry.OperationID) >= 0 {
		return fmt.Errorf("%w: %s", ErrWriteAlreadyJournaled, entry.OperationID)
	}
	entry.Method = strings.ToUpper(strings.TrimSpace(entry.Method))
	entry.RedactedURL = RedactURL(entry.RedactedURL)
	entry.State = WriteStateIntent
	entry.IntentAt, entry.SentAt, entry.CleanupAt = journalNow(), "", ""
	return j.commitLocked(append(slices.Clone(j.entries), entry))
}

// MarkSent records that the target answered the write.
func (j *WriteJournal) MarkSent(operationID string) error {
	return j.transition(operationID, WriteStateIntent, func(e *WriteJournalEntry) {
		e.State, e.SentAt = WriteStateSent, journalNow()
	})
}

// MarkCleanup records the outcome of a sent write's declared cleanup.
func (j *WriteJournal) MarkCleanup(operationID string, succeeded bool) error {
	return j.transition(operationID, WriteStateSent, func(e *WriteJournalEntry) {
		e.State = WriteStateCleanupFailed
		if succeeded {
			e.State = WriteStateCleanupDone
		}
		e.CleanupAt = journalNow()
	})
}

func (j *WriteJournal) transition(operationID string, from WriteState, apply func(*WriteJournalEntry)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	i := j.indexLocked(operationID)
	if i < 0 {
		return fmt.Errorf("write journal: unknown operation %q", operationID)
	}
	if j.entries[i].State != from {
		return fmt.Errorf("write journal: operation %q is %s, not %s", operationID, j.entries[i].State, from)
	}
	next := slices.Clone(j.entries)
	apply(&next[i])
	return j.commitLocked(next)
}

func (j *WriteJournal) indexLocked(operationID string) int {
	return slices.IndexFunc(j.entries, func(e WriteJournalEntry) bool { return e.OperationID == operationID })
}

// commitLocked persists entries and only then adopts them in memory, so the
// in-memory journal never runs ahead of what is on disk.
func (j *WriteJournal) commitLocked(entries []WriteJournalEntry) error {
	if err := storage.EnsureSecureDir(filepath.Dir(j.path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(writeJournalFile{SchemaVersion: WriteJournalSchemaVersion, Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := storage.WriteAtomic(j.path, append(data, '\n')); err != nil {
		return err
	}
	j.entries = entries
	return nil
}

func journalNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// Package notes provides the notes tool for agent memory.
package notes

import (
	"fmt"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v3/internal/tools"
)

var (
	mu    sync.RWMutex
	store = make(map[string]string) // key → value
)

// ResetNotes clears all notes (called at scan start).
func ResetNotes() {
	mu.Lock()
	store = make(map[string]string)
	mu.Unlock()
}

// Register adds note tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "add_note",
		Description: "Add a note to the agent's memory. Notes persist across iterations.",
		Parameters: []tools.Parameter{
			{Name: "key", Description: "Unique key for the note", Required: true},
			{Name: "value", Description: "Note content", Required: true},
		},
		Execute: addNote,
	})

	r.Register(&tools.Tool{
		Name:        "read_notes",
		Description: "Read all notes or a specific note from memory.",
		Parameters: []tools.Parameter{
			{Name: "key", Description: "Key to read (omit for all notes)", Required: false},
		},
		Execute: readNotes,
	})
}

func addNote(args map[string]string) (tools.Result, error) {
	key := args["key"]
	value := args["value"]

	mu.Lock()
	store[key] = value
	mu.Unlock()

	return tools.Result{Output: fmt.Sprintf("Note saved: %s", key)}, nil
}

func readNotes(args map[string]string) (tools.Result, error) {
	key := args["key"]

	mu.RLock()
	defer mu.RUnlock()

	if key != "" {
		v, ok := store[key]
		if !ok {
			return tools.Result{Output: fmt.Sprintf("No note found with key: %s", key)}, nil
		}
		return tools.Result{Output: v}, nil
	}

	if len(store) == 0 {
		return tools.Result{Output: "(no notes yet)"}, nil
	}

	var b strings.Builder
	for k, v := range store {
		b.WriteString(fmt.Sprintf("📝 %s:\n%s\n\n", k, v))
	}
	return tools.Result{Output: b.String()}, nil
}

// GetAllNotes returns all notes as a map (for server-side access).
func GetAllNotes() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	result := make(map[string]string, len(store))
	for k, v := range store {
		result[k] = v
	}
	return result
}

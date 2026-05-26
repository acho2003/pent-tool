package fileedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestStrReplaceEditor_CreateViewReplaceAndInsert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")

	res, err := strReplaceEditor(map[string]string{
		"command":   "create",
		"path":      path,
		"file_text": "alpha\nbeta\ngamma\n",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.Contains(res.Output, "File created") {
		t.Fatalf("unexpected create output: %s", res.Output)
	}

	res, err = strReplaceEditor(map[string]string{
		"command":    "view",
		"path":       path,
		"view_range": "2-2",
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if !strings.Contains(res.Output, "beta") || strings.Contains(res.Output, "alpha") {
		t.Fatalf("view range output = %q", res.Output)
	}

	if _, err = strReplaceEditor(map[string]string{
		"command": "str_replace",
		"path":    path,
		"old_str": "beta",
		"new_str": "BETA",
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	if _, err = strReplaceEditor(map[string]string{
		"command":     "insert",
		"path":        path,
		"insert_line": "2",
		"new_str":     "inserted",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read edited file: %v", err)
	}
	if got := string(data); got != "alpha\nBETA\ninserted\ngamma\n" {
		t.Fatalf("edited file = %q", got)
	}
}

func TestReplaceInFile_RequiresUniqueOldString(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dupes.txt")
	if err := os.WriteFile(path, []byte("same\nsame\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	_, err := replaceInFile(path, "same", "new")
	if err == nil || !strings.Contains(err.Error(), "found 2 times") {
		t.Fatalf("replace duplicate error = %v", err)
	}

	_, err = replaceInFile(path, "missing", "new")
	if err == nil || !strings.Contains(err.Error(), "old_str not found") {
		t.Fatalf("replace missing error = %v", err)
	}
}

func TestInsertAndViewValidateRanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if _, err := insertInFile(path, "x", "not-a-number"); err == nil || !strings.Contains(err.Error(), "invalid insert_line") {
		t.Fatalf("invalid insert_line error = %v", err)
	}
	if _, err := insertInFile(path, "x", "99"); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("out-of-range insert error = %v", err)
	}
	if _, err := viewFile(path, "bad-2"); err == nil || !strings.Contains(err.Error(), "invalid start line") {
		t.Fatalf("invalid view range error = %v", err)
	}
}

func TestListFiles_EmptyAndPopulatedDirectory(t *testing.T) {
	dir := t.TempDir()
	res, err := listFiles(map[string]string{"path": dir})
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if strings.TrimSpace(res.Output) != "(empty directory)" {
		t.Fatalf("empty list output = %q", res.Output)
	}

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	res, err = listFiles(map[string]string{"path": dir})
	if err != nil {
		t.Fatalf("list populated: %v", err)
	}
	if !strings.Contains(res.Output, "a.txt") || !strings.Contains(res.Output, "subdir/") {
		t.Fatalf("populated list output = %q", res.Output)
	}
}

func TestContextFileEditorStaysInsideScanWorkspace(t *testing.T) {
	sc := scanctx.New("fileedit-scope", t.TempDir())
	sc.Terminal.SetWorkDir(sc.ScanDir)
	scanctx.Activate(sc)
	defer scanctx.Deactivate(sc.ID)

	// In-scan-workspace writes go through sandbox.Default().CheckResolve
	// and resolve relative to sc.ScanDir, which lives under /tmp and is
	// therefore inside the Path_Policy Allow_List.
	if _, err := strReplaceEditorForContext(sc.ID, map[string]string{
		"command":   "create",
		"path":      "notes.txt",
		"file_text": "scoped",
	}); err != nil {
		t.Fatalf("create in scan workspace: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sc.ScanDir, "notes.txt")); err != nil {
		t.Fatalf("expected file in scan workspace: %v", err)
	}

	// A write target outside every Allow_List root (Data_Dir, ~/.xalgorix, /tmp)
	// is rejected by Policy.CheckResolve. The error is returned to the agent
	// loop via tools.Result{Error: ...}, nil — never as a Go-level error —
	// so the LLM can recover and retry under an allowed root.
	res, err := strReplaceEditorForContext(sc.ID, map[string]string{
		"command":   "create",
		"path":      "/etc/xalgorix-fileedit-test-outside.txt",
		"file_text": "outside",
	})
	if err != nil {
		t.Fatalf("path-policy reject must be returned via Result.Error, not Go error: %v", err)
	}
	if !strings.Contains(res.Error, "path-policy reject") {
		t.Fatalf("expected path-policy reject error, got Result.Error=%q output=%q", res.Error, res.Output)
	}
	if !strings.Contains(res.Error, "fileedit.create") {
		t.Fatalf("expected tool name fileedit.create in error, got %q", res.Error)
	}
	if _, statErr := os.Stat("/etc/xalgorix-fileedit-test-outside.txt"); statErr == nil {
		t.Fatalf("rejected path must not have been written")
	}
}

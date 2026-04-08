// Package fileedit provides file editing, listing, and searching tools.
package fileedit

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v3/internal/config"
	"github.com/xalgord/xalgorix/v3/internal/tools"
)

// Register adds file editing tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "str_replace_editor",
		Description: "Edit a file by replacing text. Use command=view to view, command=create to create, command=str_replace to edit, command=insert to insert.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "One of: view, create, str_replace, insert", Required: true},
			{Name: "path", Description: "File path (relative to workspace or absolute)", Required: true},
			{Name: "old_str", Description: "Text to find (for str_replace)", Required: false},
			{Name: "new_str", Description: "Replacement text (for str_replace/insert)", Required: false},
			{Name: "insert_line", Description: "Line number to insert after (for insert)", Required: false},
			{Name: "view_range", Description: "Line range to view, e.g. '1-50' (for view)", Required: false},
			{Name: "file_text", Description: "Full file content (for create)", Required: false},
		},
		Execute: strReplaceEditor,
	})

	r.Register(&tools.Tool{
		Name:        "list_files",
		Description: "List files and directories at the given path.",
		Parameters: []tools.Parameter{
			{Name: "path", Description: "Directory path to list (relative to workspace or absolute)", Required: true},
		},
		Execute: listFiles,
	})

	r.Register(&tools.Tool{
		Name:        "search_files",
		Description: "Search for a pattern in files using ripgrep (rg).",
		Parameters: []tools.Parameter{
			{Name: "pattern", Description: "Search pattern (regex)", Required: true},
			{Name: "path", Description: "Directory to search in", Required: false},
			{Name: "include", Description: "File glob to include (e.g. *.go)", Required: false},
		},
		Execute: searchFiles,
	})
}

func resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return config.Get().WorkspacePath(path)
}

func strReplaceEditor(args map[string]string) (tools.Result, error) {
	command := args["command"]
	path := resolvePath(args["path"])

	switch command {
	case "view":
		return viewFile(path, args["view_range"])
	case "create":
		return createFile(path, args["file_text"])
	case "str_replace":
		return replaceInFile(path, args["old_str"], args["new_str"])
	case "insert":
		return insertInFile(path, args["new_str"], args["insert_line"])
	default:
		return tools.Result{}, fmt.Errorf("unknown command: %s (expected: view, create, str_replace, insert)", command)
	}
}

func viewFile(path, viewRange string) (tools.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read file: %w", err)
	}

	lines := strings.Split(string(data), "\n")

	startLine, endLine := 1, len(lines)
	if viewRange != "" {
		parts := strings.SplitN(viewRange, "-", 2)
		if len(parts) == 2 {
			var err error
			startLine, err = strconv.Atoi(parts[0])
			if err != nil {
				return tools.Result{}, fmt.Errorf("invalid start line in view_range: %s", parts[0])
			}
			endLine, err = strconv.Atoi(parts[1])
			if err != nil {
				return tools.Result{}, fmt.Errorf("invalid end line in view_range: %s", parts[1])
			}
		}
	}

	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}

	var b strings.Builder
	for i := startLine - 1; i < endLine; i++ {
		b.WriteString(fmt.Sprintf("%6d │ %s\n", i+1, lines[i]))
	}

	return tools.Result{Output: b.String()}, nil
}

func createFile(path, content string) (tools.Result, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return tools.Result{}, fmt.Errorf("cannot create directory: %w", err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return tools.Result{}, fmt.Errorf("cannot write file: %w", err)
	}

	return tools.Result{Output: fmt.Sprintf("File created: %s", path)}, nil
}

func replaceInFile(path, oldStr, newStr string) (tools.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read file: %w", err)
	}

	content := string(data)

	count := strings.Count(content, oldStr)
	if count == 0 {
		return tools.Result{}, fmt.Errorf("old_str not found in file. Make sure it matches exactly, including whitespace")
	}
	if count > 1 {
		return tools.Result{}, fmt.Errorf("old_str found %d times in file. It must be unique. Add more context to make it unique", count)
	}

	newContent := strings.Replace(content, oldStr, newStr, 1)

	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		return tools.Result{}, fmt.Errorf("cannot write file: %w", err)
	}

	return tools.Result{Output: fmt.Sprintf("Successfully replaced text in %s", path)}, nil
}

func insertInFile(path, newStr, insertLineStr string) (tools.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read file: %w", err)
	}

	insertLine, err := strconv.Atoi(insertLineStr)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid insert_line %q: %w", insertLineStr, err)
	}
	lines := strings.Split(string(data), "\n")

	if insertLine < 0 || insertLine > len(lines) {
		return tools.Result{}, fmt.Errorf("insert_line %d is out of range (file has %d lines)", insertLine, len(lines))
	}

	newLines := strings.Split(newStr, "\n")
	result := make([]string, 0, len(lines)+len(newLines))
	result = append(result, lines[:insertLine]...)
	result = append(result, newLines...)
	result = append(result, lines[insertLine:]...)

	if err := os.WriteFile(path, []byte(strings.Join(result, "\n")), 0o644); err != nil {
		return tools.Result{}, fmt.Errorf("cannot write file: %w", err)
	}

	return tools.Result{Output: fmt.Sprintf("Inserted %d lines after line %d in %s", len(newLines), insertLine, path)}, nil
}

func listFiles(args map[string]string) (tools.Result, error) {
	path := resolvePath(args["path"])

	entries, err := os.ReadDir(path)
	if err != nil {
		return tools.Result{}, fmt.Errorf("cannot read directory: %w", err)
	}

	var b strings.Builder
	for _, e := range entries {
		info, _ := e.Info()
		if e.IsDir() {
			b.WriteString(fmt.Sprintf("  📁 %s/\n", e.Name()))
		} else if info != nil {
			b.WriteString(fmt.Sprintf("  📄 %s (%d bytes)\n", e.Name(), info.Size()))
		} else {
			b.WriteString(fmt.Sprintf("  📄 %s\n", e.Name()))
		}
	}

	if b.Len() == 0 {
		return tools.Result{Output: "(empty directory)"}, nil
	}
	return tools.Result{Output: b.String()}, nil
}

func searchFiles(args map[string]string) (tools.Result, error) {
	pattern := args["pattern"]
	path := args["path"]
	if path == "" {
		path = "."
	}
	path = resolvePath(path)

	include := args["include"]

	// Use ripgrep if available, fallback to grep
	cmdArgs := []string{"-n", "--color=never", "-r"}
	binary := "rg"

	if include != "" {
		cmdArgs = append(cmdArgs, "--glob", include)
	}

	cmdArgs = append(cmdArgs, pattern, path)

	result, err := tools.RunCommand(binary, cmdArgs...)
	if err != nil {
		// Fallback to grep
		grepArgs := []string{"-rn", "--color=never"}
		if include != "" {
			grepArgs = append(grepArgs, "--include", include)
		}
		grepArgs = append(grepArgs, pattern, path)
		result, err = tools.RunCommand("grep", grepArgs...)
		if err != nil {
			return tools.Result{Output: "No matches found."}, nil
		}
	}

	// Truncate if too long
	lines := strings.Split(result, "\n")
	if len(lines) > 100 {
		output := strings.Join(lines[:100], "\n")
		output += fmt.Sprintf("\n\n... [%d more matches truncated]", len(lines)-100)
		return tools.Result{Output: output}, nil
	}

	return tools.Result{Output: result}, nil
}

package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoOsGetwdInFilesystemTools is the defensive guard for Task 9.5.
//
// The workspace-leak fixes in Task 9 (python/terminal workspace prep) and
// the Path_Policy work in Task 8 hinge on a single invariant: no Filesystem_Tool
// resolves a write target through os.Getwd(). Resolution must go through
// sandbox.Default().CheckResolve / sandbox.Resolve, scanctx.ScanDir, or
// cfg.WorkspaceRoot — never $CWD.
//
// Without this guard, a future refactor that re-introduces an os.Getwd()
// fallback would silently bring back the workspace-leak bug and slip past
// review. The test parses every .go file under internal/tools/, walks the
// AST, and fails if any non-test source contains a call to os.Getwd.
//
// Comments and string literals are unaffected because we only inspect AST
// call expressions, so the documentation comments in terminal.go that
// reference the historical os.Getwd() fallback do not trip the guard.
//
// Validates: Requirements 8.10, 5.5.
func TestNoOsGetwdInFilesystemTools(t *testing.T) {
	root := "."
	fset := token.NewFileSet()

	type offender struct {
		File string
		Line int
	}
	var offenders []offender

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Only Go non-test source — the guard is about production paths,
		// and tests legitimately set up CWD-relative fixtures.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "os" && sel.Sel.Name == "Getwd" {
				pos := fset.Position(call.Pos())
				offenders = append(offenders, offender{File: pos.Filename, Line: pos.Line})
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk internal/tools: %v", walkErr)
	}

	if len(offenders) > 0 {
		var b strings.Builder
		b.WriteString("os.Getwd() found in Filesystem_Tool source. ")
		b.WriteString("Filesystem tools must resolve paths through sandbox.Default().CheckResolve / ")
		b.WriteString("sandbox.Resolve, scanctx.ScanDir, or cfg.WorkspaceRoot — never $CWD. ")
		b.WriteString("Offenders:\n")
		for _, o := range offenders {
			b.WriteString("  ")
			b.WriteString(o.File)
			b.WriteString(":")
			// Avoid strconv import for a single int.
			fmtLine := func(n int) string {
				if n == 0 {
					return "0"
				}
				digits := []byte{}
				for n > 0 {
					digits = append([]byte{byte('0' + n%10)}, digits...)
					n /= 10
				}
				return string(digits)
			}
			b.WriteString(fmtLine(o.Line))
			b.WriteString("\n")
		}
		t.Fatal(b.String())
	}
}

package python

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestExecutePython_ValidationErrors(t *testing.T) {
	if _, err := executePython(map[string]string{}); err == nil {
		t.Fatal("missing code did not return an error")
	}

	res, err := executePython(map[string]string{"code": "print('x')", "timeout": "abc"})
	if err != nil {
		t.Fatalf("invalid timeout returned hard error: %v", err)
	}
	if !strings.Contains(res.Error, "invalid timeout") {
		t.Fatalf("invalid timeout result = %#v", res)
	}
}

func TestExecutePython_SuccessAndStderr(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err := exec.LookPath("python"); err != nil {
			t.Skip("python is not installed")
		}
	}

	res, err := executePython(map[string]string{
		"code":    "import sys\nprint('stdout ok')\nprint('stderr ok', file=sys.stderr)",
		"timeout": "5",
	})
	if err != nil {
		t.Fatalf("executePython returned hard error: %v", err)
	}
	if !strings.Contains(res.Output, "stdout ok") || !strings.Contains(res.Output, "STDERR:") || !strings.Contains(res.Output, "stderr ok") {
		t.Fatalf("unexpected python output: %q", res.Output)
	}
}

func TestExecutePython_UsesScanContextWorkDir(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err := exec.LookPath("python"); err != nil {
			t.Skip("python is not installed")
		}
	}

	sc := scanctx.New("python-ctx", t.TempDir())
	sc.Terminal.SetWorkDir(sc.ScanDir)
	scanctx.Activate(sc)
	defer func() {
		scanctx.Deactivate(sc.ID)
	}()

	res, err := executePythonForContext(sc.ID, map[string]string{
		"code":    "import os\nprint(os.getcwd())",
		"timeout": "5",
	})
	if err != nil {
		t.Fatalf("executePythonForContext returned hard error: %v", err)
	}
	if strings.TrimSpace(res.Output) != sc.ScanDir {
		t.Fatalf("python cwd = %q, want %q", strings.TrimSpace(res.Output), sc.ScanDir)
	}
}

func TestExecutePython_RunsInSeparateProcessGroup(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err := exec.LookPath("python"); err != nil {
			t.Skip("python is not installed")
		}
	}

	parentPGID, err := syscall.Getpgid(0)
	if err != nil {
		t.Fatalf("Getpgid(parent): %v", err)
	}

	res, err := executePython(map[string]string{
		"code":    "import os\nprint(os.getpgrp())",
		"timeout": "5",
	})
	if err != nil {
		t.Fatalf("executePython returned hard error: %v", err)
	}
	fields := strings.Fields(res.Output)
	if len(fields) == 0 {
		t.Fatalf("missing process group output: %q", res.Output)
	}
	childPGID, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("parse child process group from %q: %v", res.Output, err)
	}
	if childPGID == parentPGID {
		t.Fatalf("python_action used parent process group %d; cleanup could kill xalgorix", parentPGID)
	}
}

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xalgord/xalgorix/v4/internal/storage"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type TemplateInventory struct {
	Scanner        string   `json:"scanner"`
	PolicyVersion  string   `json:"policy_version"`
	State          string   `json:"state"`
	Templates      []string `json:"templates"`
	ExecutedChecks *int     `json:"executed_checks"`
}

// Listing asks Nuclei which templates its pinned engine enables under the
// configured policy, without giving it targets or authentication credentials.
func saveNucleiTemplateInventory(ctx context.Context, req Request, cfg Config) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	args := []string{"-tl", "-silent", "-nc", "-duc", "-dut", "-t", cfg.NucleiTemplatesDir}
	args = append(args, nucleiPolicyArgs(cfg)...)
	command := exec.CommandContext(ctx, cfg.NucleiPath, args...)
	var output limitedTemplateOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("Nuclei enabled template listing failed")
	}
	if output.exceeded {
		return "", fmt.Errorf("Nuclei template inventory exceeded metadata limit")
	}
	unique := map[string]bool{}
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			unique[line] = true
		}
	}
	templates := make([]string, 0, len(unique))
	for template := range unique {
		templates = append(templates, template)
	}
	sort.Strings(templates)
	if len(templates) == 0 {
		return "", fmt.Errorf("Nuclei enabled template inventory is empty")
	}
	data, err := json.MarshalIndent(TemplateInventory{Scanner: "nuclei", PolicyVersion: nucleiPolicyVersion, State: "enabled", Templates: templates}, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(req.ScanDir, "template-inventory.json")
	return path, storage.WriteAtomic(path, data)
}

type limitedTemplateOutput struct {
	strings.Builder
	exceeded bool
}

func (w *limitedTemplateOutput) Write(data []byte) (int, error) {
	if w.Len()+len(data) > 8<<20 {
		w.exceeded = true
		return len(data), nil
	}
	return w.Builder.Write(data)
}

// Package skills provides the read_skill and list_skills tools for on-demand knowledge loading.
package skills

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

//go:embed data/*/*
var embeddedSkills embed.FS

// Register adds skill tools to the registry.
func Register(r *tools.Registry, _ string) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		// Should not happen unless embed is empty
		subFS = embeddedSkills
	}
	r.Register(&tools.Tool{
		Name:        "read_skill",
		Description: "Load a vulnerability/protocol/framework skill to get deep testing methodology, payloads, and techniques. Use this BEFORE testing a specific vulnerability class (e.g., read_skill name=nosql_injection before testing for NoSQL injection). This gives you expert-level knowledge including exact payloads, bypass techniques, and chaining strategies that dramatically improve your testing depth.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Skill name without .md extension (e.g., nosql_injection, http_request_smuggling, oauth2_attacks, prototype_pollution). Use list_skills to see all available skills.", Required: true},
			{Name: "category", Description: "Category folder: vulnerabilities, protocols, frameworks, cloud, reconnaissance. Default: vulnerabilities", Required: false},
		},
		Execute: makeReadSkill(subFS),
	})

	r.Register(&tools.Tool{
		Name:        "list_skills",
		Description: "List all available skills organized by category. Call this to see what deep knowledge is available before deciding which skills to load for your current target's technology stack.",
		Parameters: []tools.Parameter{
			{Name: "category", Description: "Filter by category: vulnerabilities, protocols, frameworks, cloud, reconnaissance. Omit to list all.", Required: false},
		},
		Execute: makeListSkills(subFS),
	})
}

func makeReadSkill(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		name := strings.TrimSpace(args["name"])
		category := strings.TrimSpace(args["category"])
		if category == "" {
			category = "vulnerabilities"
		}

		// Sanitize — prevent path traversal
		name = filepath.Base(name)
		category = filepath.Base(category)

		if name == "" {
			return tools.Result{Error: "skill name is required"}, nil
		}

		// Add .md extension if missing
		if !strings.HasSuffix(name, ".md") {
			name = name + ".md"
		}

		skillPath := category + "/" + name

		data, err := fs.ReadFile(fsys, skillPath)
		if err != nil {
			// Try searching all categories if not found in specified one
			if category == "vulnerabilities" {
				found := searchAllCategories(fsys, name)
				if found != "" {
					return tools.Result{Output: found}, nil
				}
			}
			return tools.Result{Error: fmt.Sprintf("skill not found: %s/%s — use list_skills to see available skills", category, name)}, nil
		}

		return tools.Result{Output: string(data)}, nil
	}
}

func searchAllCategories(fsys fs.FS, name string) string {
	categories := []string{"vulnerabilities", "protocols", "frameworks", "cloud", "reconnaissance", "technologies", "scan_modes", "coordination"}
	for _, cat := range categories {
		path := cat + "/" + name
		data, err := fs.ReadFile(fsys, path)
		if err == nil {
			return string(data)
		}
	}
	return ""
}

func makeListSkills(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		filterCat := strings.TrimSpace(args["category"])

		categories := []string{"vulnerabilities", "protocols", "frameworks", "cloud", "reconnaissance", "technologies", "scan_modes", "coordination"}
		if filterCat != "" {
			categories = []string{filepath.Base(filterCat)}
		}

		var b strings.Builder
		b.WriteString("📚 Available Skills\n\n")

		totalSkills := 0
		for _, cat := range categories {
			entries, err := fs.ReadDir(fsys, cat)
			if err != nil {
				continue
			}

			var skills []string
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") || e.Name() == ".gitkeep" {
					continue
				}
				skills = append(skills, strings.TrimSuffix(e.Name(), ".md"))
			}

			if len(skills) == 0 {
				continue
			}

			sort.Strings(skills)
			totalSkills += len(skills)

			b.WriteString(fmt.Sprintf("### %s (%d skills)\n", strings.ToUpper(cat), len(skills)))
			for _, s := range skills {
				b.WriteString(fmt.Sprintf("  • %s\n", s))
			}
			b.WriteString("\n")
		}

		b.WriteString(fmt.Sprintf("Total: %d skills available\n", totalSkills))
		b.WriteString("\nUsage: read_skill(name=\"skill_name\", category=\"category\")\n")
		b.WriteString("Default category is 'vulnerabilities'\n")

		return tools.Result{Output: b.String()}, nil
	}
}

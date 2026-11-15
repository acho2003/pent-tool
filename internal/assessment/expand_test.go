package assessment

import (
	"strings"
	"testing"
)

func emisTemplate() SystemTemplate {
	return SystemTemplate{
		Name:           "EMIS NestJS",
		BaseURL:        "https://dev-emis.systems.gov.bt",
		PathTemplate:   "/svc/{name}",
		VerifyTemplate: "/svc/{name}/health",
	}
}

func TestExpandSystemTemplatePathScoping(t *testing.T) {
	exp, err := ExpandSystemTemplate(emisTemplate(), []string{"common", "academic"}, "")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(exp.Targets) != 2 || len(exp.Services) != 2 {
		t.Fatalf("want 2 targets/services, got %d/%d", len(exp.Targets), len(exp.Services))
	}
	if exp.Targets[0].Value != "https://dev-emis.systems.gov.bt/svc/common" {
		t.Fatalf("unexpected target URL %q", exp.Targets[0].Value)
	}

	// The derived scope must bound each target to its own /svc/<name> prefix.
	cfg := AssessmentConfig{Targets: exp.Targets}
	scope := AppScopeForTarget(cfg, exp.Targets[0].ID)
	if ok, _ := scope.Allows("https://dev-emis.systems.gov.bt/svc/common/accommodation-type"); !ok {
		t.Fatalf("common scope should allow its own subpath")
	}
	if ok, _ := scope.Allows("https://dev-emis.systems.gov.bt/svc/academic/terms"); ok {
		t.Fatalf("common scope must not allow a sibling service path")
	}
}

func TestExpandSystemTemplateVerifyInScope(t *testing.T) {
	exp, err := ExpandSystemTemplate(emisTemplate(), []string{"common"}, "")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	verify := exp.VerifyByID[exp.Targets[0].ID]
	if verify != "https://dev-emis.systems.gov.bt/svc/common/health" {
		t.Fatalf("unexpected verify URL %q", verify)
	}
	cfg := AssessmentConfig{Targets: exp.Targets}
	scope := AppScopeForTarget(cfg, exp.Targets[0].ID)
	if ok, reason := scope.Allows(verify); !ok {
		t.Fatalf("verify URL must be in scope: %s", reason)
	}
	if exp.Items[0].VerifyPath != "/svc/common/health" {
		t.Fatalf("unexpected verify path %q", exp.Items[0].VerifyPath)
	}
}

func TestExpandSystemTemplateStableIDsAndGrouping(t *testing.T) {
	exp, _ := ExpandSystemTemplate(emisTemplate(), []string{"health-wellbeing-service"}, "")
	if exp.Targets[0].ID != "svc-health-wellbeing-service-url" {
		t.Fatalf("unexpected target id %q", exp.Targets[0].ID)
	}
	if exp.Services[0].ID != "svc-health-wellbeing-service" {
		t.Fatalf("unexpected service id %q", exp.Services[0].ID)
	}
	if len(exp.Services[0].TargetIDs) != 1 || exp.Services[0].TargetIDs[0] != exp.Targets[0].ID {
		t.Fatalf("service must group its one target")
	}
	if len(exp.AuthTargetIDs) != 1 || exp.AuthTargetIDs[0] != exp.Targets[0].ID {
		t.Fatalf("auth target ids must list every target")
	}
}

func TestExpandSystemTemplateDedupe(t *testing.T) {
	exp, err := ExpandSystemTemplate(emisTemplate(), []string{"common", "Common", " common ", ""}, "")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(exp.Items) != 1 {
		t.Fatalf("want 1 deduped item, got %d", len(exp.Items))
	}
}

func TestExpandSystemTemplateBaseOverride(t *testing.T) {
	exp, err := ExpandSystemTemplate(emisTemplate(), []string{"common"}, "https://staging.example.test/")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if exp.Targets[0].Value != "https://staging.example.test/svc/common" {
		t.Fatalf("base override not applied: %q", exp.Targets[0].Value)
	}
}

func TestExpandSystemTemplateHeaderDefaults(t *testing.T) {
	exp, _ := ExpandSystemTemplate(emisTemplate(), []string{"common"}, "")
	if exp.HeaderName != "Authorization" || exp.HeaderPrefix != "Bearer " {
		t.Fatalf("unexpected header defaults %q / %q", exp.HeaderName, exp.HeaderPrefix)
	}
}

func TestExpandSystemTemplateSpecPath(t *testing.T) {
	tpl := emisTemplate()
	tpl.SpecMode = "path"
	tpl.SpecTemplate = "/svc/{name}/documentation-json"
	exp, err := ExpandSystemTemplate(tpl, []string{"common"}, "")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if exp.Items[0].SpecPath != "/svc/common/documentation-json" {
		t.Fatalf("unexpected spec path %q", exp.Items[0].SpecPath)
	}
}

func TestExpandSystemTemplateCap(t *testing.T) {
	names := make([]string, 0, maxExpandedServices+1)
	for i := 0; i <= maxExpandedServices; i++ {
		names = append(names, "svc"+strings.Repeat("x", 1)+itoa(i))
	}
	if _, err := ExpandSystemTemplate(emisTemplate(), names, ""); err == nil {
		t.Fatalf("expected cap error")
	}
}

func TestExpandSystemTemplateNoNames(t *testing.T) {
	if _, err := ExpandSystemTemplate(emisTemplate(), []string{"", "  "}, ""); err == nil {
		t.Fatalf("expected error for no usable names")
	}
}

func TestExpandSystemTemplateInvalidTemplate(t *testing.T) {
	bad := emisTemplate()
	bad.PathTemplate = "svc/{name}" // missing leading slash
	if _, err := ExpandSystemTemplate(bad, []string{"common"}, ""); err == nil {
		t.Fatalf("expected invalid template error")
	}
}

// itoa avoids importing strconv for one call in the cap test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

package assessment

import "testing"

func TestRelatedTargetsNormalizeAndRejectUnknownOrSelf(t *testing.T) {
	base := AssessmentConfig{Mode: ModeWhiteBox, Types: []Type{TypeSourceCode, TypeWebApplication}, Targets: []Target{{ID: "src", Kind: KindLocalSourcePath, Value: "/source/app"}, {ID: "web", Kind: KindURL, Value: "https://app.example.test", RelatedTo: " src "}}}
	normalized := Normalize(base)
	if normalized.Targets[1].RelatedTo != "src" {
		t.Fatal("relationship ID not normalized")
	}
	for _, id := range []string{"missing", "web"} {
		cfg := normalized
		cfg.Targets = append([]Target(nil), normalized.Targets...)
		cfg.Targets[1].RelatedTo = id
		found := false
		for _, problem := range Validate(cfg) {
			if problem.Code == "target.related_to.invalid" {
				found = true
			}
		}
		if !found {
			t.Fatal("invalid related target accepted")
		}
	}
}

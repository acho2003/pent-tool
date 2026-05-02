package resources

import "testing"

func TestLevelStringAndMaxLevel(t *testing.T) {
	if LevelOK.String() != "OK" || LevelCaution.String() != "CAUTION" || LevelCritical.String() != "CRITICAL" {
		t.Fatalf("unexpected level strings: %s %s %s", LevelOK, LevelCaution, LevelCritical)
	}
	if Level(99).String() != "UNKNOWN" {
		t.Fatalf("unknown level string = %s", Level(99))
	}
	if got := maxLevel(LevelCaution, LevelCritical); got != LevelCritical {
		t.Fatalf("maxLevel = %s, want CRITICAL", got)
	}
	if got := maxLevel(LevelCaution, LevelOK); got != LevelCaution {
		t.Fatalf("maxLevel = %s, want CAUTION", got)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("XALGORIX_TEST_FLOAT", "")
	if got := envFloat("XALGORIX_TEST_FLOAT", 1.5); got != 1.5 {
		t.Fatalf("envFloat default = %v", got)
	}
	t.Setenv("XALGORIX_TEST_FLOAT", "2.25")
	if got := envFloat("XALGORIX_TEST_FLOAT", 1.5); got != 2.25 {
		t.Fatalf("envFloat parsed = %v", got)
	}
	t.Setenv("XALGORIX_TEST_FLOAT", "bad")
	if got := envFloat("XALGORIX_TEST_FLOAT", 1.5); got != 1.5 {
		t.Fatalf("envFloat invalid default = %v", got)
	}

	t.Setenv("XALGORIX_TEST_INT", "7")
	if got := envInt64("XALGORIX_TEST_INT", 3); got != 7 {
		t.Fatalf("envInt64 parsed = %v", got)
	}
	t.Setenv("XALGORIX_TEST_INT", "bad")
	if got := envInt64("XALGORIX_TEST_INT", 3); got != 3 {
		t.Fatalf("envInt64 invalid default = %v", got)
	}
}

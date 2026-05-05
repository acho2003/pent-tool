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

	t.Setenv("XALGORIX_OPTIONAL_INT", "")
	if got := envOptionalInt("XALGORIX_OPTIONAL_INT"); got != 0 {
		t.Fatalf("envOptionalInt empty = %v", got)
	}
	t.Setenv("XALGORIX_OPTIONAL_INT", "4")
	if got := envOptionalInt("XALGORIX_OPTIONAL_INT"); got != 4 {
		t.Fatalf("envOptionalInt parsed = %v", got)
	}
	t.Setenv("XALGORIX_OPTIONAL_INT", "0")
	if got := envOptionalInt("XALGORIX_OPTIONAL_INT"); got != 0 {
		t.Fatalf("envOptionalInt invalid cap = %v", got)
	}
}

func TestPerInstanceMemoryBudgetIncludesToolAndOverhead(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldOverhead := scanOverheadMB
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		scanOverheadMB = oldOverhead
	})

	HeavyToolMemLimitBytes = 1500 * 1024 * 1024
	scanOverheadMB = 700
	if got := perInstanceMemoryBudgetMB(); got != 2200 {
		t.Fatalf("perInstanceMemoryBudgetMB = %d, want 2200", got)
	}

	HeavyToolMemLimitBytes = 0
	scanOverheadMB = 128
	if got := perInstanceMemoryBudgetMB(); got != 1024 {
		t.Fatalf("perInstanceMemoryBudgetMB minimum = %d, want 1024", got)
	}
}

func TestEffectiveMaxInstancesUsesDynamicResourceCapacity(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldOverhead := scanOverheadMB
	oldCriticalRAM := ramCriticalMB
	oldCPUCritical := cpuCriticalPct
	oldCPUBudget := perScanCPULoad
	oldManualCap := manualMaxInstances
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		scanOverheadMB = oldOverhead
		ramCriticalMB = oldCriticalRAM
		cpuCriticalPct = oldCPUCritical
		perScanCPULoad = oldCPUBudget
		manualMaxInstances = oldManualCap
	})

	HeavyToolMemLimitBytes = 1500 * 1024 * 1024
	scanOverheadMB = 500
	ramCriticalMB = 1000
	cpuCriticalPct = 90
	perScanCPULoad = 1
	manualMaxInstances = 0

	stats := SystemStats{
		CPUCores:       8,
		LoadAvg1m:      1.0,
		MemAvailableMB: 11000,
	}
	got, _ := effectiveMaxInstancesForStats(stats, LevelOK, "OK")
	if got != 5 {
		t.Fatalf("dynamic instances = %d, want 5 from RAM capacity", got)
	}

	manualMaxInstances = 3
	got, _ = effectiveMaxInstancesForStats(stats, LevelOK, "OK")
	if got != 3 {
		t.Fatalf("manual cap dynamic instances = %d, want 3", got)
	}

	manualMaxInstances = 0
	got, _ = effectiveMaxInstancesForStats(stats, LevelCritical, "RAM critical")
	if got != 0 {
		t.Fatalf("critical dynamic instances = %d, want 0", got)
	}
}

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
	oldBudget := scanMemoryBudgetMB
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		scanOverheadMB = oldOverhead
		scanMemoryBudgetMB = oldBudget
	})

	HeavyToolMemLimitBytes = 1500 * 1024 * 1024
	scanOverheadMB = 700
	scanMemoryBudgetMB = 2048
	if got := perInstanceMemoryBudgetMB(); got != 2200 {
		t.Fatalf("perInstanceMemoryBudgetMB expands to fit explicit tool limit = %d, want 2200", got)
	}

	HeavyToolMemLimitBytes = 0
	scanOverheadMB = 128
	scanMemoryBudgetMB = 2048
	if got := perInstanceMemoryBudgetMB(); got != 2048 {
		t.Fatalf("perInstanceMemoryBudgetMB default budget = %d, want 2048", got)
	}

	scanMemoryBudgetMB = 512
	if got := perInstanceMemoryBudgetMB(); got != 1024 {
		t.Fatalf("perInstanceMemoryBudgetMB floor = %d, want 1024", got)
	}
}

func TestAutoHeavyToolLimitFitsInsideScanBudget(t *testing.T) {
	oldOverhead := scanOverheadMB
	oldBudget := scanMemoryBudgetMB
	t.Cleanup(func() {
		scanOverheadMB = oldOverhead
		scanMemoryBudgetMB = oldBudget
	})

	scanMemoryBudgetMB = 2048
	scanOverheadMB = 384
	if got := autoHeavyToolMemLimitMB(8192); got != 1664 {
		t.Fatalf("autoHeavyToolMemLimitMB(8GB) = %d, want 1664", got)
	}

	if got := autoHeavyToolMemLimitMB(4096); got != 1024 {
		t.Fatalf("autoHeavyToolMemLimitMB(4GB) = %d, want 1024", got)
	}
}

func TestEffectiveMaxInstancesUsesDynamicResourceCapacity(t *testing.T) {
	oldLimit := HeavyToolMemLimitBytes
	oldOverhead := scanOverheadMB
	oldBudget := scanMemoryBudgetMB
	oldCriticalRAM := ramCriticalMB
	oldCPUCritical := cpuCriticalPct
	oldCPUBudget := perScanCPULoad
	oldManualCap := manualMaxInstances
	t.Cleanup(func() {
		HeavyToolMemLimitBytes = oldLimit
		scanOverheadMB = oldOverhead
		scanMemoryBudgetMB = oldBudget
		ramCriticalMB = oldCriticalRAM
		cpuCriticalPct = oldCPUCritical
		perScanCPULoad = oldCPUBudget
		manualMaxInstances = oldManualCap
	})

	HeavyToolMemLimitBytes = 1500 * 1024 * 1024
	scanOverheadMB = 500
	scanMemoryBudgetMB = 2048
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
	if got != 4 {
		t.Fatalf("dynamic instances = %d, want 4 from RAM capacity", got)
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

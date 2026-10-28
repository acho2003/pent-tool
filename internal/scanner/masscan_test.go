package scanner

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildMasscanUsesFixedCommonPortsAndConservativeRate(t *testing.T) {
	cfg := Config{MasscanPath: "masscan", MasscanRate: 100, MasscanTimeout: time.Minute}
	spec := buildMasscan(Request{Target: "192.0.2.0/24", ScanDir: "/tmp/scan"}, cfg)
	if spec.notApp != "" || spec.path != "masscan" || spec.timeout != time.Minute {
		t.Fatalf("unexpected spec: %+v", spec)
	}
	want := []string{"-p", masscanPorts, "--rate", "100", "--wait", "3", "-oJ", "/tmp/scan/scanner-output/masscan/results.json", "192.0.2.0/24"}
	if !reflect.DeepEqual(spec.args, want) {
		t.Fatalf("Masscan args = %#v, want %#v", spec.args, want)
	}
}

func TestBuildMasscanRejectsBroadMalformedAndUnsupportedTargets(t *testing.T) {
	for _, target := range []string{"192.0.2.1/24", "192.0.0.0/19", "2001:db8::1", "example.test", "-oJ"} {
		if spec := buildMasscan(Request{Target: target, ScanDir: t.TempDir()}, Config{MasscanPath: "masscan"}); spec.notApp == "" {
			t.Errorf("target %q was accepted", target)
		}
	}
	if spec := buildMasscan(Request{Target: "192.0.2.10", ScanDir: t.TempDir()}, Config{MasscanPath: "masscan", MasscanRate: 1001}); spec.notApp == "" {
		t.Fatal("excessive packet rate was accepted")
	}
}

func TestMasscanLeaseSerializesExecutionsAndHonorsCancellation(t *testing.T) {
	release, err := acquireMasscan(context.Background(), "masscan")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := acquireMasscan(ctx, "/usr/local/bin/masscan"); err != context.DeadlineExceeded {
		t.Fatalf("second lease error = %v", err)
	}
	release()
	releaseAgain, err := acquireMasscan(context.Background(), "masscan")
	if err != nil {
		t.Fatalf("lease was not released: %v", err)
	}
	releaseAgain()
}

func TestBuildMasscanConsultsTheScopeGuard(t *testing.T) {
	var seen []string
	cfg := Config{MasscanPath: "masscan", MasscanRate: 100, MasscanTimeout: time.Minute,
		ScopeGuard: func(_ string, resolved []string) (bool, string) {
			seen = resolved
			for _, a := range resolved {
				if a == "127.0.0.1" {
					return true, "scope guard: resolved address 127.0.0.1 is the scanner host"
				}
			}
			return false, ""
		}}
	spec := buildMasscan(Request{Target: "127.0.0.1", ScanDir: t.TempDir()}, cfg)
	if spec.notApp == "" || !strings.Contains(spec.notApp, "scanner host") {
		t.Fatalf("masscan must refuse a guarded address: %q (seen=%v)", spec.notApp, seen)
	}
	if len(seen) == 0 {
		t.Fatalf("the scope guard was not consulted")
	}
	if spec := buildMasscan(Request{Target: "192.0.2.10", ScanDir: t.TempDir()}, cfg); spec.notApp != "" {
		t.Fatalf("an allowed address was refused: %q", spec.notApp)
	}
	// A CIDR is judged by its network address, like nmap.
	if spec := buildMasscan(Request{Target: "192.0.2.0/24", ScanDir: t.TempDir()}, cfg); spec.notApp != "" {
		t.Fatalf("an allowed network was refused: %q", spec.notApp)
	}
}

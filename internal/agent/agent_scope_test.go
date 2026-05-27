package agent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestShouldBlockForOutOfScope_BlocksThirdPartyHost is the regression
// test for the "agent reports findings on unrelated host" bug
// (Grafana on 159.223.74.62:9999 turning up in a scan of
// pentest-ground.com). The agent must reject any tool call whose
// arguments name a host that isn't the configured target or a
// subdomain of it.
func TestShouldBlockForOutOfScope_BlocksThirdPartyHost(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		tool string
		args map[string]string
	}{
		{
			name: "terminal_execute against unrelated IP",
			tool: "terminal_execute",
			args: map[string]string{
				"command": "curl http://159.223.74.62:9999/?title=%22%3E%3Csvg/onload=alert(1)%3E",
			},
		},
		{
			name: "report_vulnerability with unrelated target field",
			tool: "report_vulnerability",
			args: map[string]string{
				"title":    "XSS in Grafana",
				"target":   "http://159.223.74.62:9999",
				"endpoint": "http://159.223.74.62:9999/?title=%3Csvg",
				"severity": "high",
			},
		},
		{
			name: "browser_action navigating to unrelated host",
			tool: "browser_action",
			args: map[string]string{
				"action": "navigate",
				"url":    "https://attacker.example/callback",
			},
		},
		{
			name: "python_action requesting unrelated host",
			tool: "python_action",
			args: map[string]string{
				"code": "import requests; requests.get('http://example.org/admin')",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args)
			if !blocked {
				t.Fatalf("expected %s with args %v to be blocked, got allow", tc.tool, tc.args)
			}
			if reason == "" {
				t.Fatalf("expected non-empty rejection reason")
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsInScope confirms the guard does
// not block legitimate tool calls against the configured target or
// its subdomains.
func TestShouldBlockForOutOfScope_AllowsInScope(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		tool string
		args map[string]string
	}{
		{
			name: "exact target",
			tool: "terminal_execute",
			args: map[string]string{"command": "nmap -sV pentest-ground.com"},
		},
		{
			name: "subdomain",
			tool: "terminal_execute",
			args: map[string]string{"command": "curl https://api.pentest-ground.com/v1/users"},
		},
		{
			name: "URL form with port",
			tool: "browser_action",
			args: map[string]string{"url": "https://app.pentest-ground.com:8443/admin"},
		},
		{
			name: "report_vulnerability against subdomain",
			tool: "report_vulnerability",
			args: map[string]string{
				"target":   "https://api.pentest-ground.com",
				"endpoint": "https://api.pentest-ground.com/v1/users",
				"title":    "IDOR",
				"severity": "high",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args); blocked {
				t.Fatalf("expected %s with args %v to be allowed, got blocked: %s", tc.tool, tc.args, reason)
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsHostlessCommands confirms tool
// calls that don't name any host (local artifact analysis like grep,
// awk, jq over recon output files) are allowed.
func TestShouldBlockForOutOfScope_AllowsHostlessCommands(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []map[string]string{
		{"command": "ls -la"},
		{"command": "grep 'password' notes.json"},
		{"command": "jq '.vulns[]' scan.json"},
		{"command": "wc -l live_subdomains.txt"},
	}
	for _, args := range cases {
		if blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args); blocked {
			t.Fatalf("hostless command %v should be allowed, got blocked: %s", args, reason)
		}
	}
}

// TestShouldBlockForOutOfScope_DisabledWhenNoScope confirms the gate
// is a no-op when no activity hosts are configured. A scope-less scan
// (CLI mode without targets piped in) shouldn't fail every tool call.
func TestShouldBlockForOutOfScope_DisabledWhenNoScope(t *testing.T) {
	a := &Agent{}
	// activityHosts left empty
	if blocked, _ := a.shouldBlockForOutOfScope("terminal_execute",
		map[string]string{"command": "curl http://anywhere.example"}); blocked {
		t.Fatal("expected guard to be disabled when activityHosts is empty")
	}
}

// TestExtractHostFromTokenForScope tests the host-extraction primitive
// for the variety of token shapes the agent emits.
func TestExtractHostFromTokenForScope(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/path", "example.com"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"159.223.74.62", "159.223.74.62"},
		{"159.223.74.62:9999", "159.223.74.62"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"./script.sh", ""},
		{"/tmp/foo.txt", ""},
		{"../etc/passwd", ""},
		{"v1.2.3", ""},
		{"1.2.3", ""},
		{"--rate-limit", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractHostFromTokenForScope(tc.in)
		if got != tc.want {
			t.Errorf("extractHostFromTokenForScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHostInScope tests the scope membership primitive.
func TestHostInScope(t *testing.T) {
	hosts := []string{"pentest-ground.com", "another.example"}
	cases := []struct {
		in   string
		want bool
	}{
		{"pentest-ground.com", true},
		{"api.pentest-ground.com", true},
		{"deep.nested.api.pentest-ground.com", true},
		{"another.example", true},
		{"sub.another.example", true},
		// Suffix attack: must not match.
		{"evilpentest-ground.com", false},
		{"pentest-ground.com.attacker.example", false},
		// Unrelated.
		{"159.223.74.62", false},
		{"google.com", false},
		// Empty host = always in-scope (caller's call).
		{"", true},
	}
	for _, tc := range cases {
		got := hostInScope(tc.in, hosts)
		if got != tc.want {
			t.Errorf("hostInScope(%q, %v) = %v, want %v", tc.in, hosts, got, tc.want)
		}
	}
}

// TestExtractHostsFromArgs verifies multi-token extraction.
func TestExtractHostsFromArgs(t *testing.T) {
	args := map[string]string{
		"command": `curl -H "Host: api.example.com" https://example.com/foo && nmap evil.org`,
	}
	hosts := extractHostsFromArgs(args)
	got := strings.Join(hosts, ",")
	// Order is insertion-order; the actual hosts must include the three
	// distinct ones from the command.
	for _, want := range []string{"api.example.com", "example.com", "evil.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", args, hosts, want)
		}
	}
}

// TestExtractHostsFromArgs_QueryParamRedirect locks in the URL-sweep
// path. URLs nested inside query parameters, fragments, or bare
// `key=value` forms must surface their embedded host alongside the
// outer in-scope host so the gate sees the full set, and a gated
// tool that names the wrapped OOS host must be rejected.
//
// Validates Requirements 1.2, 1.3, 1.5, 1.6.
func TestExtractHostsFromArgs_QueryParamRedirect(t *testing.T) {
	extractCases := []struct {
		name     string
		args     map[string]string
		wantAll  []string
		wantNone []string
	}{
		{
			name:    "redirect param surfaces both hosts",
			args:    map[string]string{"url": "https://in-scope.example/redirect?next=https://oos.example/path"},
			wantAll: []string{"in-scope.example", "oos.example"},
		},
		{
			name:    "fragment-embedded URL surfaces both hosts",
			args:    map[string]string{"url": "https://in-scope.example/page#https://oos.example/p"},
			wantAll: []string{"in-scope.example", "oos.example"},
		},
		{
			name:    "bare key=value pair splits and extracts host",
			args:    map[string]string{"url": "next=evil.example"},
			wantAll: []string{"evil.example"},
		},
		{
			// Req 1.5: in-scope host, OOS host, filename, and
			// version-like token in one value — the host-classification
			// rules must apply to each token independently.
			name:     "mix of in-scope, OOS, filename, and version",
			args:     map[string]string{"command": "scanner --version v1.2.3 --in pentest-ground.com --out notes.json target=evil.example"},
			wantAll:  []string{"pentest-ground.com", "evil.example"},
			wantNone: []string{"notes.json", "v1.2.3", "1.2.3"},
		},
		{
			// Req 1.6: the URL-sweep helper hits "https://user:pass"
			// (which url.Parse rejects with "invalid port"). The sweep
			// must drop it silently and the separator pass must still
			// recover the trailing bare host.
			name:    "malformed URL then bare host",
			args:    map[string]string{"url": "https://user:pass evil.example"},
			wantAll: []string{"evil.example"},
		},
	}
	for _, tc := range extractCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hosts := extractHostsFromArgs(tc.args)
			joined := "," + strings.Join(hosts, ",") + ","
			for _, want := range tc.wantAll {
				if !strings.Contains(joined, ","+want+",") {
					t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", tc.args, hosts, want)
				}
			}
			for _, none := range tc.wantNone {
				if strings.Contains(joined, ","+none+",") {
					t.Errorf("extractHostsFromArgs(%v) = %v, %q must not appear", tc.args, hosts, none)
				}
			}
		})
	}

	// Req 1.3: a redirect-style URL whose query parameter wraps an
	// OOS host must cause a gated tool call to be rejected, with the
	// rejection reason naming the OOS host.
	t.Run("gated tool blocked on wrapped OOS host", func(t *testing.T) {
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		args := map[string]string{
			"url": "https://app.pentest-ground.com/redirect?next=https://oos.example/path",
		}
		blocked, reason := a.shouldBlockForOutOfScope("browser_action", args)
		if !blocked {
			t.Fatalf("expected redirect-style OOS URL to be blocked, got allow")
		}
		if !strings.Contains(reason, "oos.example") {
			t.Errorf("rejection reason should name the OOS host, got %q", reason)
		}
	})
}

// TestExtractHostsFromArgs_UserinfoForm locks in the userinfo-aware
// extraction path. Both the bare `user@host` shape (caught by the
// new `@` separator in scopeHostTokenSplit) and the
// `https://user:pass@host` shape (caught by url.Parse via the URL
// sweep) must surface the host portion case-insensitively, and a
// gated tool naming a userinfo-wrapped OOS host must be rejected.
//
// Validates Requirement 1.4.
func TestExtractHostsFromArgs_UserinfoForm(t *testing.T) {
	extractCases := []struct {
		name string
		args map[string]string
		want string
	}{
		{
			name: "bare user@host",
			args: map[string]string{"target": "user@oos.example"},
			want: "oos.example",
		},
		{
			name: "case-insensitive bare user@host",
			args: map[string]string{"target": "USER@OOS.EXAMPLE"},
			want: "oos.example",
		},
		{
			name: "userinfo URL",
			args: map[string]string{"target": "https://user:pass@oos.example"},
			want: "oos.example",
		},
		{
			name: "case-insensitive userinfo URL",
			args: map[string]string{"target": "https://USER:PASS@OOS.EXAMPLE"},
			want: "oos.example",
		},
	}
	for _, tc := range extractCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hosts := extractHostsFromArgs(tc.args)
			found := false
			for _, h := range hosts {
				if h == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", tc.args, hosts, tc.want)
			}
		})
	}

	// Gated-tool path: a userinfo-wrapped OOS host inside a
	// terminal_execute command must be blocked, naming the OOS host.
	t.Run("gated tool blocked on userinfo OOS host", func(t *testing.T) {
		a := &Agent{}
		a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})
		for _, raw := range []string{
			"user@oos.example",
			"https://user:pass@oos.example",
		} {
			args := map[string]string{"command": "curl " + raw}
			blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args)
			if !blocked {
				t.Errorf("expected userinfo OOS form %q to be blocked, got allow", raw)
				continue
			}
			if !strings.Contains(reason, "oos.example") {
				t.Errorf("rejection reason for %q should name oos.example, got %q", raw, reason)
			}
		}
	})
}

// TestScopeHostTokenSplit_NewSeparators pins the separator switch to
// the four runes added in Wave A — `=`, `?`, `#`, and `@` — without
// regressing the pre-existing whitespace and shell metacharacter
// boundaries.
//
// Validates Requirement 1.1.
func TestScopeHostTokenSplit_NewSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "equals splits",
			in:   "key=evil.example",
			want: []string{"key", "evil.example"},
		},
		{
			name: "question splits",
			in:   "host.example?id=1",
			want: []string{"host.example", "id", "1"},
		},
		{
			name: "fragment splits",
			in:   "host.example#anchor",
			want: []string{"host.example", "anchor"},
		},
		{
			name: "at splits",
			in:   "user@oos.example",
			want: []string{"user", "oos.example"},
		},
		{
			name: "all four new separators together",
			in:   "k=v?p#f@h",
			want: []string{"k", "v", "p", "f", "h"},
		},
		{
			name: "pre-existing separators still split",
			in:   "a,b;c|d&e<f>g",
			want: []string{"a", "b", "c", "d", "e", "f", "g"},
		},
		{
			name: "whitespace, brackets, and quotes still split",
			in:   "a\tb\nc \"d\" 'e' (f) [g] {h}",
			want: []string{"a", "b", "c", "d", "e", "f", "g", "h"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := scopeHostTokenSplit(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("scopeHostTokenSplit(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestExtractHostsFromArgs_LongValueTruncated locks in the 8 KiB
// per-value scan cap. Host-shaped tokens that sit past the
// argScanLimitBytes boundary must be ignored, and the gate must not
// block, deny, or fail a tool call solely because the argument is
// long.
//
// Validates Requirements 2.1, 2.2.
func TestExtractHostsFromArgs_LongValueTruncated(t *testing.T) {
	const oosHost = "evil.example"
	const inScopeHost = "in.example"

	// Build a payload whose first argScanLimitBytes bytes contain an
	// in-scope host and whose tail (past byte 8192) contains an OOS
	// host. The OOS host must not surface from extractHostsFromArgs.
	var b strings.Builder
	b.WriteString(inScopeHost)
	b.WriteByte(' ')
	// Pad with whitespace-separated junk until we are well past the
	// 8 KiB cap, then append the OOS host.
	pad := strings.Repeat("x ", argScanLimitBytes)
	b.WriteString(pad)
	b.WriteString(oosHost)
	long := b.String()
	if len(long) <= argScanLimitBytes {
		t.Fatalf("test setup: long value should exceed the cap, got %d bytes", len(long))
	}

	hosts := extractHostsFromArgs(map[string]string{"command": long})
	joined := "," + strings.Join(hosts, ",") + ","
	if !strings.Contains(joined, ","+inScopeHost+",") {
		t.Errorf("in-scope host before cap missing: hosts=%v", hosts)
	}
	if strings.Contains(joined, ","+oosHost+",") {
		t.Errorf("OOS host past the 8 KiB cap must be ignored, got hosts=%v", hosts)
	}

	// Req 2.2: a gated tool whose OOS reference sits entirely past
	// the cap must not be blocked.
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://" + inScopeHost})
	if blocked, reason := a.shouldBlockForOutOfScope("terminal_execute",
		map[string]string{"command": long}); blocked {
		t.Fatalf("OOS reference past the 8 KiB cap must not block, got blocked: %s", reason)
	}

	// And: a value that is simply long with no host-shaped tokens at
	// all must produce no hosts and must not raise an error.
	hostlessLong := strings.Repeat("x ", argScanLimitBytes*2)
	if got := extractHostsFromArgs(map[string]string{"command": hostlessLong}); len(got) != 0 {
		t.Errorf("hostless long value should produce no hosts, got %v", got)
	}
}

// TestExtractHostsFromArgs_ShortValueUnaffected pins the
// behavior-preservation guarantee for values whose byte length is
// at or below the 8 KiB cap: tokenization must walk the entire
// value and return the same host set the implementation produced
// before the cap was introduced.
//
// Validates Requirement 2.3.
func TestExtractHostsFromArgs_ShortValueUnaffected(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "short value, host at end",
			value: "scan target evil.example",
			want:  []string{"evil.example"},
		},
		{
			name:  "two hosts in a short value",
			value: "curl https://example.com/foo && nmap evil.org",
			want:  []string{"example.com", "evil.org"},
		},
		{
			name: "value of exactly argScanLimitBytes bytes with host at the end",
			value: strings.Repeat("x ", (argScanLimitBytes-len("evil.example"))/2) +
				"evil.example",
			want: []string{"evil.example"},
		},
		{
			name: "value of argScanLimitBytes-1 bytes with host at the end",
			value: strings.Repeat("x ", (argScanLimitBytes-1-len("evil.example"))/2) +
				" evil.example",
			want: []string{"evil.example"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.value) > argScanLimitBytes {
				t.Fatalf("test setup: value must be <= cap, got %d bytes", len(tc.value))
			}
			hosts := extractHostsFromArgs(map[string]string{"command": tc.value})
			joined := "," + strings.Join(hosts, ",") + ","
			for _, want := range tc.want {
				if !strings.Contains(joined, ","+want+",") {
					t.Errorf("extractHostsFromArgs(%q) = %v, missing %q", tc.value, hosts, want)
				}
			}
		})
	}
}

// TestTruncateForScopeScan_UTF8Boundary pins the rune-boundary trim
// behavior of truncateForScopeScan. When the 8 KiB cap falls inside
// a multi-byte UTF-8 sequence, the helper must walk back to the
// largest byte offset <= argScanLimitBytes that lies on a rune
// start, and the returned string must be valid UTF-8 so downstream
// FieldsFunc never sees a partial rune.
//
// Validates Requirement 2.4.
func TestTruncateForScopeScan_UTF8Boundary(t *testing.T) {
	// "✓" is U+2713, encoded as 3 bytes (0xE2 0x9C 0x93).
	const checkmark = "\u2713"
	if utf8.RuneLen('\u2713') != 3 {
		t.Fatalf("test setup: expected ✓ to be 3 bytes")
	}

	t.Run("value at or below cap returned unchanged", func(t *testing.T) {
		short := "https://example.com/path"
		if got := truncateForScopeScan(short); got != short {
			t.Errorf("short value should be returned unchanged, got %q", got)
		}
		exact := strings.Repeat("a", argScanLimitBytes)
		if got := truncateForScopeScan(exact); got != exact {
			t.Errorf("value of exactly cap length should be returned unchanged (len=%d)", len(got))
		}
	})

	t.Run("cap inside multi-byte rune walks back to rune start", func(t *testing.T) {
		// Place an ASCII pad of (cap-2) bytes then a checkmark so the
		// checkmark's bytes live at offsets cap-2, cap-1, cap. The
		// cap index argScanLimitBytes itself sits on the trailing
		// byte of the checkmark, which is a continuation byte.
		pad := strings.Repeat("a", argScanLimitBytes-2)
		v := pad + checkmark + checkmark
		if len(v) <= argScanLimitBytes {
			t.Fatalf("test setup: v must exceed cap, got %d bytes", len(v))
		}
		got := truncateForScopeScan(v)
		if len(got) > argScanLimitBytes {
			t.Errorf("truncated length %d exceeds cap %d", len(got), argScanLimitBytes)
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncated string must be valid UTF-8, got %q", got)
		}
		// The first checkmark spans bytes [cap-2, cap-1, cap]; since
		// the cap byte is a continuation, the helper must walk back
		// to argScanLimitBytes-2 (the rune start of the first
		// checkmark).
		if len(got) != argScanLimitBytes-2 {
			t.Errorf("expected truncation back to cap-2 (%d), got %d", argScanLimitBytes-2, len(got))
		}
		if got != pad {
			t.Errorf("truncated string should equal the ASCII pad, got %q", got)
		}
		// And: the truncated string must not panic when fed into the
		// downstream FieldsFunc-based tokenizer.
		_ = scopeHostTokenSplit(got)
	})

	t.Run("cap exactly on rune boundary keeps the prefix", func(t *testing.T) {
		// Pad with cap bytes of ASCII, then append a checkmark. The
		// cap index sits on the lead byte of the checkmark, which is
		// itself a rune start, so the helper returns the prefix
		// untouched at exactly cap bytes.
		pad := strings.Repeat("a", argScanLimitBytes)
		v := pad + checkmark
		got := truncateForScopeScan(v)
		if len(got) != argScanLimitBytes {
			t.Errorf("expected truncation length cap (%d), got %d", argScanLimitBytes, len(got))
		}
		if got != pad {
			t.Errorf("truncated string should equal the ASCII pad")
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncated string must be valid UTF-8")
		}
	})
}

// runAddNoteRedaction mirrors the pre-gate redaction step the agent
// loop runs at internal/agent/agent.go (~line 1633) before
// shouldBlockForOutOfScope. It walks `key` and `value` independently,
// applies redactOutOfScopeHosts, and writes the rewritten string
// back into args when the substitution count is non-zero. Returning
// the total count lets the wiring tests assert end-to-end behaviour
// without booting the full agent loop. Kept tiny on purpose so the
// production wiring it stands in for stays the source of truth.
func runAddNoteRedaction(a *Agent, args map[string]string) int {
	if len(a.activityHosts) == 0 {
		return 0
	}
	total := 0
	for _, k := range []string{"key", "value"} {
		if v, ok := args[k]; ok {
			if r, n := a.redactOutOfScopeHosts(v); n > 0 {
				args[k] = r
				total += n
			}
		}
	}
	return total
}

// TestRedactOutOfScopeHosts_BasicReplace pins the core behaviour of
// the redact helper: every OOS host span is replaced in place with
// the literal marker `[redacted: out-of-scope host]`, the
// substitution count matches the number of distinct OOS spans, and
// the rewriter handles the three shapes the URL sweep and separator
// pass surface (bare host, full URL, userinfo, query-style
// `key=URL`). Tokenization mirrors extractHostsFromArgs.
//
// Validates Requirements 4.1, 4.2, 4.5.
func TestRedactOutOfScopeHosts_BasicReplace(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	const marker = "[redacted: out-of-scope host]"

	cases := []struct {
		name      string
		in        string
		wantOut   string
		wantCount int
	}{
		{
			name:      "bare OOS host",
			in:        "saw evil.example today",
			wantOut:   "saw " + marker + " today",
			wantCount: 1,
		},
		{
			name:      "OOS URL with path",
			in:        "visit https://oos.example/path now",
			wantOut:   "visit " + marker + " now",
			wantCount: 1,
		},
		{
			name:      "userinfo bare form (split on @ separator)",
			in:        "ssh user@oos.example",
			wantOut:   "ssh user@" + marker,
			wantCount: 1,
		},
		{
			name:      "redirect query parameter",
			in:        "go=https://oos.example/redirect",
			wantOut:   "go=" + marker,
			wantCount: 1,
		},
		{
			name:      "two distinct OOS hosts in one value",
			in:        "first evil.example then evil2.example",
			wantOut:   "first " + marker + " then " + marker,
			wantCount: 2,
		},
		{
			name:      "OOS host inside redirect-style URL",
			in:        "https://app.pentest-ground.com/redirect?next=https://oos.example/path",
			wantOut:   "https://app.pentest-ground.com/redirect?next=" + marker,
			wantCount: 1,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, count := a.redactOutOfScopeHosts(tc.in)
			if got != tc.wantOut {
				t.Errorf("redactOutOfScopeHosts(%q)\n got = %q\nwant = %q", tc.in, got, tc.wantOut)
			}
			if count != tc.wantCount {
				t.Errorf("redactOutOfScopeHosts(%q) count = %d, want %d", tc.in, count, tc.wantCount)
			}
			if !strings.Contains(got, marker) {
				t.Errorf("redaction marker missing from output %q", got)
			}
		})
	}
}

// TestRedactOutOfScopeHosts_PreservesInScope locks in the
// no-mutation guarantee for in-scope inputs: when every host in the
// value is in-scope (or no host is named at all), the helper must
// return the input string byte-identical and a zero substitution
// count. This is the read_notes round-trip safety net — legitimate
// notes referencing the configured target must not be mangled.
//
// Validates Requirements 4.3, 4.4, 4.5, 4.8.
func TestRedactOutOfScopeHosts_PreservesInScope(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		in   string
	}{
		{
			name: "configured host bare",
			in:   "found CSRF token on pentest-ground.com",
		},
		{
			name: "configured host as URL",
			in:   "visit https://app.pentest-ground.com/login soon",
		},
		{
			name: "subdomain URL with path and query",
			in:   "GET https://api.pentest-ground.com/v1/users?id=1&role=admin",
		},
		{
			name: "no host tokens at all",
			in:   "scan completed, see notes.json for output",
		},
		{
			name: "configured host plus filename and version token",
			in:   "wrote https://pentest-ground.com to scan.txt v1.2.3",
		},
		{
			name: "empty string",
			in:   "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, count := a.redactOutOfScopeHosts(tc.in)
			if got != tc.in {
				t.Errorf("redactOutOfScopeHosts(%q) mutated string to %q, expected byte-identical passthrough", tc.in, got)
			}
			if count != 0 {
				t.Errorf("redactOutOfScopeHosts(%q) count = %d, want 0", tc.in, count)
			}
			if strings.Contains(got, "[redacted: out-of-scope host]") {
				t.Errorf("in-scope value should not contain the redaction marker, got %q", got)
			}
		})
	}

	// Empty activityHosts → redact path is a no-op even for
	// host-shaped inputs. Matches the shouldBlockForOutOfScope
	// short-circuit and keeps scope-less CLI runs from corrupting
	// notes.
	t.Run("empty activityHosts is no-op", func(t *testing.T) {
		bare := &Agent{}
		got, count := bare.redactOutOfScopeHosts("saw evil.example today")
		if got != "saw evil.example today" {
			t.Errorf("no-scope agent should not redact, got %q", got)
		}
		if count != 0 {
			t.Errorf("no-scope agent should report zero redactions, got %d", count)
		}
	})
}

// TestAddNote_RedactsOOSInKeyAndValue exercises the agent loop's
// add_note pre-gate wiring (internal/agent/agent.go ~line 1633). A
// ToolCall named `add_note` whose `key` and `value` arguments each
// reference an OOS host must have both arguments rewritten in place
// with the redaction marker substituted, the call must be allowed
// to proceed (shouldBlockForOutOfScope returns allow on the rewritten
// args because the OOS tokens are gone), and the gated-tool list
// must remain unchanged.
//
// Validates Requirements 4.1, 4.2, 4.3, 4.6, 4.7.
func TestAddNote_RedactsOOSInKeyAndValue(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	const marker = "[redacted: out-of-scope host]"

	args := map[string]string{
		"key":   "leak_from_oos.example",
		"value": "found at https://evil.example/dump and also tracker.example",
	}

	total := runAddNoteRedaction(a, args)
	if total < 2 {
		t.Errorf("expected at least 2 total redactions across key+value, got %d", total)
	}

	if !strings.Contains(args["key"], marker) {
		t.Errorf("key should contain redaction marker, got %q", args["key"])
	}
	if strings.Contains(args["key"], "oos.example") {
		t.Errorf("key still contains OOS host: %q", args["key"])
	}

	if !strings.Contains(args["value"], marker) {
		t.Errorf("value should contain redaction marker, got %q", args["value"])
	}
	if strings.Contains(args["value"], "evil.example") {
		t.Errorf("value still contains OOS host evil.example: %q", args["value"])
	}
	if strings.Contains(args["value"], "tracker.example") {
		t.Errorf("value still contains OOS host tracker.example: %q", args["value"])
	}

	// Req 4.3: post-redaction the gate must allow add_note. (add_note
	// is not in the gated tool list, so this is a belt-and-braces
	// check that the OOS-clean rewritten args don't surface any host
	// that would trip a hypothetical future gate addition.)
	if blocked, reason := a.shouldBlockForOutOfScope("add_note", args); blocked {
		t.Errorf("add_note must be allowed after redaction, got blocked: %s", reason)
	}

	// Req 4.6: the gated reject path must NOT invoke the redactor.
	// Re-run a Gated_Tool with the same OOS shape and confirm the
	// args are still byte-identical to the inputs (i.e. the gated
	// rejection path leaves them alone — only the redact wiring
	// mutates).
	gatedArgs := map[string]string{"command": "curl https://evil.example/dump"}
	want := gatedArgs["command"]
	blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", gatedArgs)
	if !blocked {
		t.Fatalf("gated tool with OOS host should be rejected, got allow")
	}
	if !strings.Contains(reason, "evil.example") {
		t.Errorf("gated rejection reason should name evil.example, got %q", reason)
	}
	if gatedArgs["command"] != want {
		t.Errorf("gated path mutated args (redactor leaked into reject path): %q", gatedArgs["command"])
	}
}

// TestAddNote_NoOpWhenAllInScope locks in the byte-identical
// passthrough guarantee from Requirement 4.4: when neither argument
// of an add_note call references any OOS host, both arguments must
// reach the tool handler exactly as the LLM emitted them, and the
// redaction wiring must not raise an error or mutate the args even
// when one of the documented arguments is missing or non-host (Req
// 4.8). Also exercises the empty-activityHosts short-circuit.
//
// Validates Requirements 4.4, 4.6, 4.8.
func TestAddNote_NoOpWhenAllInScope(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		args map[string]string
	}{
		{
			name: "both args reference in-scope host",
			args: map[string]string{
				"key":   "csrf_token_app",
				"value": "found at https://app.pentest-ground.com/login",
			},
		},
		{
			name: "neither arg names a host",
			args: map[string]string{
				"key":   "phase_done",
				"value": "recon complete, see notes.json",
			},
		},
		{
			name: "value reference subdomain via URL with path+query",
			args: map[string]string{
				"key":   "user_endpoint",
				"value": "GET https://api.pentest-ground.com/v1/users?id=1",
			},
		},
		{
			name: "missing key argument (Req 4.8 passthrough)",
			args: map[string]string{
				"value": "ok",
			},
		},
		{
			name: "missing value argument (Req 4.8 passthrough)",
			args: map[string]string{
				"key": "phase_done",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Snapshot the original args so the comparison is
			// byte-identical even if the wiring mutates the map.
			before := make(map[string]string, len(tc.args))
			for k, v := range tc.args {
				before[k] = v
			}

			total := runAddNoteRedaction(a, tc.args)
			if total != 0 {
				t.Errorf("expected zero redactions for in-scope/missing-arg input, got %d", total)
			}
			for k, want := range before {
				if got := tc.args[k]; got != want {
					t.Errorf("arg %q mutated: got %q, want %q", k, got, want)
				}
			}
			if len(tc.args) != len(before) {
				t.Errorf("args map size changed: got %d entries, want %d", len(tc.args), len(before))
			}
			for _, v := range tc.args {
				if strings.Contains(v, "[redacted: out-of-scope host]") {
					t.Errorf("in-scope arg gained a redaction marker: %q", v)
				}
			}
		})
	}

	// Empty activityHosts: the wiring's `len(a.activityHosts) > 0`
	// guard short-circuits the path entirely, so even an OOS-rich
	// arg set passes through untouched.
	t.Run("empty activityHosts short-circuits the wiring", func(t *testing.T) {
		bare := &Agent{}
		args := map[string]string{
			"key":   "leak_from_oos.example",
			"value": "saw https://evil.example/dump",
		}
		want := map[string]string{
			"key":   "leak_from_oos.example",
			"value": "saw https://evil.example/dump",
		}
		total := runAddNoteRedaction(bare, args)
		if total != 0 {
			t.Errorf("scope-less agent should not redact, got %d", total)
		}
		for k, v := range want {
			if args[k] != v {
				t.Errorf("scope-less wiring mutated %q: got %q, want %q", k, args[k], v)
			}
		}
	})
}

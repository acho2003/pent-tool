package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompleteXMLDocument(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", false},
		{"<get_tasks_response status=\"200\">", false},
		{"<get_tasks_response status=\"200\"><task id=\"1\"><status>Done</status>", false},
		{"<get_tasks_response status=\"200\"/>", true},
		{"<get_tasks_response><task><status>Done</status></task></get_tasks_response>", true},
	} {
		if got := completeXMLDocument([]byte(tc.in)); got != tc.want {
			t.Errorf("completeXMLDocument(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestGMPStatusError(t *testing.T) {
	if err := gmpStatusError([]byte(`<authenticate_response status="200" status_text="OK"/>`)); err != nil {
		t.Errorf("200 must not be an error: %v", err)
	}
	err := gmpStatusError([]byte(`<authenticate_response status="400" status_text="Authentication failed"/>`))
	if err == nil || !strings.Contains(err.Error(), "Authentication failed") {
		t.Errorf("400 error = %v", err)
	}
	if gmpStatusError([]byte(`<nostatus/>`)) == nil {
		t.Error("a response without a status must be an error")
	}
}

func TestXMLIDByExactNamePrefersTheExactMatch(t *testing.T) {
	data := []byte(`<get_configs_response status="200">` +
		`<config id="deep"><name>Full and very deep</name></config>` +
		`<config id="fast"><name>Full and fast</name></config></get_configs_response>`)
	if got := xmlIDByExactName(data, "config", "Full and fast"); got != "fast" {
		t.Errorf("id = %q, want %q", got, "fast")
	}
	if got := xmlIDByExactName(data, "config", "Nothing like it"); got != "deep" {
		t.Errorf("fallback id = %q, want the first config", got)
	}
}

// fakeGvmd speaks enough GMP over a UNIX socket to drive one full OpenVAS run.
type fakeGvmd struct {
	mu       sync.Mutex
	commands []string
	// taskStatus is what get_tasks reports; empty means "Done".
	taskStatus   string
	taskProgress []int
	polls        int
	stopFails    bool
	noPortList   bool
}

func (f *fakeGvmd) seen(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.commands {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeGvmd) serve(t *testing.T, conn net.Conn) {
	defer conn.Close()
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if err != nil {
			return
		}
		for completeXMLDocument(buf.Bytes()) {
			command := buf.String()
			buf.Reset()
			f.mu.Lock()
			f.commands = append(f.commands, command)
			f.mu.Unlock()
			if _, err := conn.Write([]byte(f.respond(command))); err != nil {
				return
			}
		}
	}
}

func (f *fakeGvmd) respond(command string) string {
	root := ""
	d := xml.NewDecoder(strings.NewReader(command))
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		if s, ok := tok.(xml.StartElement); ok {
			root = s.Name.Local
			break
		}
	}
	switch root {
	case "authenticate":
		return `<authenticate_response status="200" status_text="OK"/>`
	case "get_configs":
		return `<get_configs_response status="200">` +
			`<config id="cfg-deep"><name>Full and very deep</name></config>` +
			`<config id="cfg-fast"><name>Full and fast</name></config></get_configs_response>`
	case "get_scanners":
		return `<get_scanners_response status="200">` +
			`<scanner id="scn-cve"><name>CVE</name></scanner>` +
			`<scanner id="scn-default"><name>OpenVAS Default</name></scanner></get_scanners_response>`
	case "get_port_lists":
		if f.noPortList {
			return `<get_port_lists_response status="200"/>`
		}
		return `<get_port_lists_response status="200">` +
			`<port_list id="pl-tcp-udp"><name>All IANA assigned TCP and UDP</name></port_list>` +
			`<port_list id="pl-tcp"><name>All IANA assigned TCP</name></port_list></get_port_lists_response>`
	case "create_target":
		return `<create_target_response status="201" status_text="OK" id="tgt-1"/>`
	case "create_task":
		return `<create_task_response status="201" status_text="OK" id="task-1"/>`
	case "start_task":
		return `<start_task_response status="202" status_text="OK"><report_id>rep-1</report_id></start_task_response>`
	case "get_tasks":
		f.mu.Lock()
		progress := 100
		if len(f.taskProgress) > 0 {
			index := f.polls
			if index >= len(f.taskProgress) {
				index = len(f.taskProgress) - 1
			}
			progress = f.taskProgress[index]
		}
		f.polls++
		f.mu.Unlock()
		status := f.taskStatus
		if status == "" {
			status = "Done"
		}
		return fmt.Sprintf(`<get_tasks_response status="200"><task id="task-1"><name>t</name><status>%s</status><progress>%d</progress></task></get_tasks_response>`, status, progress)
	case "stop_task":
		if f.stopFails {
			return `<stop_task_response status="400" status_text="stop denied"/>`
		}
		return `<stop_task_response status="202" status_text="OK, request submitted"/>`
	case "get_reports":
		// Real gvmd shape: the result-bearing <report> is nested in an outer one.
		return `<get_reports_response status="200"><report id="rep-1" format_id="a994b278"><name>r</name><report id="rep-1"><results>` +
			`<result id="res-1"><name>Deprecated TLS</name><host>example.test<asset asset_id="a1"/><hostname/></host><port>443/tcp</port>` +
			`<threat>Medium</threat><severity>5.3</severity><description>legacy protocol</description>` +
			`<nvt oid="1.3.6.1.4.1.25623.1.0.1"><cve>CVE-2021-0000</cve><cvss_base>5.3</cvss_base></nvt>` +
			`</result></results></report></report></get_reports_response>`
	}
	return `<response status="404" status_text="unknown command"/>`
}

func TestOpenVASRunAgainstFakeGvmd(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "gmp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "gvmd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("UNIX socket unavailable: %v", err)
	}
	defer listener.Close()
	fake := &fakeGvmd{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go fake.serve(t, conn)
		}
	}()

	dir := t.TempDir()
	cfg := Config{GVMSocket: socket, GVMUser: "admin", GVMPass: "gvm-secret", OpenVASTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	var progressEvents []Event
	run := openVASRunner{}.Run(t.Context(), Request{Target: "https://example.test/app", ScanDir: dir}, cfg, func(e Event) {
		if e.Type == "scanner_progress" {
			progressEvents = append(progressEvents, e)
		}
	})

	if run.Status != "completed" {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
	// gvmd's <progress> is published while the task runs and cleared once done.
	if len(progressEvents) != 1 || progressEvents[0].Run.Progress != 100 || progressEvents[0].Run.ProgressStage != "scan" {
		t.Fatalf("progress events = %+v", progressEvents)
	}
	if run.Progress != 0 || run.ProgressStage != "" {
		t.Fatalf("completed run kept stale progress: %d %q", run.Progress, run.ProgressStage)
	}
	if !fake.seen(`<config id="cfg-fast"/>`) {
		t.Error("task was not created with the exact-match Full and fast config")
	}
	if !fake.seen(`<scanner id="scn-default"/>`) {
		t.Error("task was not created with the OpenVAS Default scanner")
	}
	if !fake.seen("<hosts>example.test</hosts>") {
		t.Error("target host was not derived from the URL")
	}
	if !fake.seen(`<port_list id="pl-tcp"/>`) {
		t.Error("target was not created with the exact-match All IANA assigned TCP port list")
	}
	// gvmd's default results view pages at rows=10; the export must disable
	// pagination or every result after the first ten is dropped.
	if !fake.seen(`ignore_pagination="1"`) || !fake.seen(`rows=-1`) {
		t.Error("report export did not request every result (pagination left on)")
	}
	findings, err := parseOpenVAS(run.ArtifactPath)
	if err != nil || len(findings) != 1 || findings[0].CVE != "CVE-2021-0000" {
		t.Fatalf("parsed report = %+v err = %v", findings, err)
	}
	log, err := os.ReadFile(run.StdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "gvm-secret") {
		t.Error("GMP password leaked into the scanner log")
	}
	if strings.Contains(string(log), "<result id=") {
		t.Error("full report XML was mirrored into the scanner log")
	}
	credentialed := openVASRunner{}.Run(t.Context(), Request{Target: "host.example.test", ScanDir: t.TempDir(), TypedAssessment: true, GVMSSHCredentialID: "58ff2793-2dc7-43fe-85f9-20bfac5a87e4", GVMSSHPort: 2222}, cfg, nil)
	if credentialed.Status != "completed" || !fake.seen(`<ssh_credential id="58ff2793-2dc7-43fe-85f9-20bfac5a87e4"><port>2222</port></ssh_credential>`) {
		t.Fatalf("target-bound Greenbone SSH credential was not attached: %+v", credentialed)
	}
	invalid := openVASRunner{}.Run(t.Context(), Request{Target: "host.example.test", ScanDir: t.TempDir(), TypedAssessment: true, GVMSSHCredentialID: `bad" id="injected`, GVMSSHPort: 22}, cfg, nil)
	if invalid.Status != "failed" || !strings.Contains(invalid.Reason, "invalid target-bound") {
		t.Fatalf("unsafe credential reference was accepted: %+v", invalid)
	}
}

func TestOpenVASStopsStalledTask(t *testing.T) {
	oldIdle, oldPoll := openVASIdleTimeout, openVASPollInterval
	openVASIdleTimeout, openVASPollInterval = 35*time.Millisecond, 5*time.Millisecond
	defer func() { openVASIdleTimeout, openVASPollInterval = oldIdle, oldPoll }()
	for _, stopFails := range []bool{false, true} {
		t.Run(fmt.Sprint("stopFails=", stopFails), func(t *testing.T) {
			socketDir, err := os.MkdirTemp("", "gmp")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(socketDir)
			socket := filepath.Join(socketDir, "gvmd.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			fake := &fakeGvmd{taskStatus: "Running", taskProgress: []int{0}, stopFails: stopFails}
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go fake.serve(t, conn)
				}
			}()
			run := openVASRunner{}.Run(t.Context(), Request{Target: "example.test", ScanDir: t.TempDir()}, Config{GVMSocket: socket, GVMUser: "admin", GVMPass: "secret", OpenVASTimeout: time.Second, MaxOutputBytes: 1 << 20}, nil)
			if run.Status != "failed" || !strings.Contains(run.Reason, "no progress") || !fake.seen("<stop_task") {
				t.Fatalf("stalled run: %+v", run)
			}
			if stopFails && !strings.Contains(run.Reason, "remote task may still be running") {
				t.Fatalf("missing stop failure: %s", run.Reason)
			}
		})
	}
}

func TestOpenVASRunFailsOnGMPErrorStatus(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "gmp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "gvmd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("UNIX socket unavailable: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
					if _, err := conn.Write([]byte(`<authenticate_response status="400" status_text="Authentication failed"/>`)); err != nil {
						return
					}
				}
			}()
		}
	}()

	run := openVASRunner{}.Run(t.Context(), Request{Target: "example.test", ScanDir: t.TempDir()},
		Config{GVMSocket: socket, GVMUser: "admin", GVMPass: "wrong", OpenVASTimeout: 15 * time.Second, MaxOutputBytes: 1 << 20}, nil)
	if run.Status != "failed" || !strings.Contains(run.Reason, "Authentication failed") {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
}

func TestOpenVASStopsGreenboneTaskWhenCancelled(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "gmp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "gvmd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("UNIX socket unavailable: %v", err)
	}
	defer listener.Close()
	fake := &fakeGvmd{taskStatus: "Running"}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go fake.serve(t, conn)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(300*time.Millisecond, cancel)
	cfg := Config{GVMSocket: socket, GVMUser: "admin", GVMPass: "gvm-secret", OpenVASTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	run := openVASRunner{}.Run(ctx, Request{Target: "https://example.test/app", ScanDir: t.TempDir()}, cfg, nil)
	if run.Status != "cancelled" {
		t.Fatalf("status = %q reason = %q", run.Status, run.Reason)
	}
	// A cancelled scan must not leave its task scanning in Greenbone.
	if !fake.seen(`<stop_task task_id="task-1"/>`) {
		t.Fatal("cancelled OpenVAS run did not stop its Greenbone task")
	}
}

func TestOpenVASInlinePortPolicyDoesNotRequireFeedPortList(t *testing.T) {
	socketDir, err := os.MkdirTemp("", "gmp-policy")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "gvmd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skip(err)
	}
	defer listener.Close()
	fake := &fakeGvmd{noPortList: true}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go fake.serve(t, connection)
		}
	}()
	cfg := Config{GVMSocket: socket, GVMUser: "admin", GVMPass: "fixture-secret", OpenVASTimeout: 30 * time.Second, MaxOutputBytes: 1 << 20}
	run := openVASRunner{}.Run(t.Context(), Request{Target: "https://example.test/app", ScanDir: t.TempDir(), NetworkPorts: []int{443, 8443, 443}}, cfg, nil)
	if run.Status != "completed" || !fake.seen("<port_range>T:443,8443</port_range>") || fake.seen("get_port_lists") {
		t.Fatalf("inline policy depended on default list: %+v", run)
	}
	if len(run.NetworkPorts) != 2 {
		t.Fatal("duplicate policy ports", run.NetworkPorts)
	}
}

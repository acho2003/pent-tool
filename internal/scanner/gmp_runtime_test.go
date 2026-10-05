package scanner

import (
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestNativeGMPReadOnlyVersion(t *testing.T) {
	socket := os.Getenv("XALGORIX_TEST_GMP_SOCKET")
	if socket == "" {
		t.Skip("read-only existing Greenbone socket opt-in")
	}
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(conn, "<get_version/>"); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Status  string `xml:"status,attr"`
		Version string `xml:"version"`
	}
	if err := xml.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "200" || response.Version == "" {
		t.Fatalf("GMP version unavailable: %+v", response)
	}
	t.Logf("existing Greenbone GMP version %s; no authentication or scan task performed", response.Version)
}

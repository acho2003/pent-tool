// Command stagedlab serves the staged assessment lab from fixed addresses so a
// disposable container network can host it. Every value is synthetic. Do not
// publish these ports on a public interface.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/xalgord/xalgorix/v4/test/stagedlab"
)

func main() {
	primary := flag.String("primary", ":8080", "approved HTTP origin listen address")
	secondary := flag.String("secondary", ":8443", "approved HTTPS origin listen address")
	alias := flag.String("alias", ":8081", "unapproved alias origin listen address")
	control := flag.String("control", ":9000", "recorder control listen address")
	aliasURL := flag.String("alias-url", "http://lab-alias:8081", "public URL pages use to reach the alias origin")
	secondaryURL := flag.String("secondary-url", "https://lab-secondary:8443", "public URL pages use to reach the secondary origin")
	flag.Parse()

	lab := stagedlab.New()
	lab.AliasURL = *aliasURL
	lab.SecondaryURL = *secondaryURL
	serve := func(name, addr string, start func(*httptest.Server), handler http.Handler) {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		server := httptest.NewUnstartedServer(handler)
		_ = server.Listener.Close()
		server.Listener = listener
		start(server)
		log.Printf("%s listening on %s", name, listener.Addr())
	}
	serve("primary", *primary, (*httptest.Server).Start, lab.PrimaryHandler())
	serve("secondary", *secondary, (*httptest.Server).StartTLS, lab.SecondaryHandler())
	serve("alias", *alias, (*httptest.Server).Start, lab.AliasHandler())
	log.Fatal(http.ListenAndServe(*control, lab.ControlHandler()))
}

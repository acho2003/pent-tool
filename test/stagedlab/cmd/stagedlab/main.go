// Command stagedlab serves the staged assessment lab from fixed addresses so a
// disposable container network can host it. Every value is synthetic. Do not
// publish these ports on a public interface.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/xalgord/xalgorix/v4/test/stagedlab"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	primary := flag.String("primary", ":8080", "approved HTTP origin listen address")
	secondary := flag.String("secondary", ":8443", "approved HTTPS origin listen address")
	alias := flag.String("alias", ":8081", "unapproved alias origin listen address")
	control := flag.String("control", ":9000", "recorder control listen address")
	aliasURL := flag.String("alias-url", "http://lab-alias:8081", "public URL pages use to reach the alias origin")
	services := map[string]*string{
		"svc-auth":    flag.String("svc-auth", ":8090", "microservice auth origin listen address"),
		"svc-orders":  flag.String("svc-orders", ":8091", "microservice orders origin listen address"),
		"svc-reports": flag.String("svc-reports", ":8092", "microservice reports origin listen address"),
		"svc-stray":   flag.String("svc-stray", ":8093", "microservice origin that never receives a token"),
	}
	secondaryURL := flag.String("secondary-url", "https://lab-secondary:8443", "public URL pages use to reach the secondary origin")
	htpasswdUser := flag.String("htpasswd", "", "print a bcrypt htpasswd line for this user (password from STAGED_REGISTRY_PASSWORD) and exit")
	flag.Parse()
	if *htpasswdUser != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("STAGED_REGISTRY_PASSWORD")), bcrypt.DefaultCost)
		if err != nil || os.Getenv("STAGED_REGISTRY_PASSWORD") == "" {
			log.Fatal("STAGED_REGISTRY_PASSWORD is required")
		}
		fmt.Printf("%s:%s\n", *htpasswdUser, hash)
		return
	}

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
	for _, name := range stagedlab.ServiceOrigins {
		serve(name, *services[name], (*httptest.Server).Start, lab.ServiceHandler(name))
	}
	log.Fatal(http.ListenAndServe(*control, lab.ControlHandler()))
}

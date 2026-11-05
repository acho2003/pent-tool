package scanner

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/xalgord/xalgorix/v4/internal/assessment"
)

// Local browser trust is explicit and exact-origin, never a wildcard browser
// security switch. Only Docker's host alias and loopback hosts are eligible.
func trustedBrowserLocalOrigin(configured []string, target string) string {
	targetURL, err := url.Parse(target)
	if err != nil {
		return ""
	}
	for _, raw := range configured {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme != "http" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		ip, ipErr := netip.ParseAddr(host)
		if host != "host.docker.internal" && host != "localhost" && (ipErr != nil || !ip.IsLoopback()) {
			continue
		}
		if u.Scheme == targetURL.Scheme && strings.EqualFold(u.Host, targetURL.Host) {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

func configureLocalBrowserLaunch(launch *launcher.Launcher, origin string) {
	if origin != "" {
		launch.Set("unsafely-treat-insecure-origin-as-secure", origin)
	}
}

func configureLocalBrowserPermission(browser *rod.Browser, origin string) error {
	if origin == "" {
		return nil
	}
	granted := false
	for _, name := range []string{"local-network-access", "local-network", "loopback-network"} {
		if err := (proto.BrowserSetPermission{Permission: &proto.BrowserPermissionDescriptor{Name: name}, Setting: "granted", Origin: origin}).Call(browser); err == nil {
			granted = true
		}
	}
	if !granted {
		return fmt.Errorf("browser could not grant the configured local development origin permission")
	}
	return nil
}

// Install before document code. Document sockets are limited to explicit
// same-origin Next development HMR; other transports are unsupported.
func browserSocketBoundaryScript(origin string, allowHMR bool) string {
	raw, _ := json.Marshal(origin)
	allow := "false"
	if allowHMR {
		allow = "true"
	}
	return fmt.Sprintf(`(() => {
 const approved = %s, allowHMR = %s;
 globalThis.__xalgorixBlockedSocket = false;
 const Native = globalThis.WebSocket;
 if (Native) globalThis.WebSocket = new Proxy(Native, {construct(target, args, newTarget) {
  const u = new URL(String(args[0]), location.href);
  const httpOrigin = (u.protocol === 'wss:' ? 'https:' : u.protocol === 'ws:' ? 'http:' : '') + '//' + u.host;
  if (u.username || u.password || !allowHMR || httpOrigin !== approved || !['/_next/hmr','/_next/webpack-hmr'].includes(u.pathname)) {globalThis.__xalgorixBlockedSocket = true; throw new DOMException('WebSocket is outside the approved browser request boundary', 'SecurityError');}
  return Reflect.construct(target,args,newTarget);
 }});
 if (globalThis.WebTransport) globalThis.WebTransport = new Proxy(globalThis.WebTransport,{construct() {globalThis.__xalgorixBlockedSocket = true; throw new DOMException('WebTransport is outside the approved browser request boundary','SecurityError');}});
})()`, raw, allow)
}

const browserLoginGETGuard = `(() => {
 globalThis.__xalgorixBlockedPasswordGET = false;
 document.addEventListener('submit', event => {
  const form = event.target;
  if (event.defaultPrevented || !(form instanceof HTMLFormElement)) return;
  if (form.method.toLowerCase() === 'get' && form.querySelector('input[type="password"]')) {
   event.preventDefault(); globalThis.__xalgorixBlockedPasswordGET = true;
  }
 });
})()`

func browserHMRAllowed(scope *assessment.AppScope, origin string) bool {
	if scope == nil || origin == "" {
		return false
	}
	for _, path := range []string{"/_next/hmr", "/_next/webpack-hmr"} {
		if ok, _ := scope.Allows(origin + path); !ok {
			return false
		}
		if excluded, _ := scope.Excluded("GET", origin+path); excluded {
			return false
		}
	}
	return true
}

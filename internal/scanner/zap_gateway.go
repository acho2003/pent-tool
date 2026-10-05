package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Install only while the dedicated daemon lease is held. Snapshot all settings
// before mutation; refuse to overwrite an existing enabled upstream proxy.
func configureZAPGateway(cfg Config, call zapCallFunc, gateway *RecordingGateway) (func() error, error) {
	state, err := call("/JSON/network/view/isHttpProxyEnabled/", url.Values{})
	if err != nil {
		return nil, fmt.Errorf("network add-on required for scoped ZAP execution")
	}
	if valueString(state, "isHttpProxyEnabled") != "false" {
		return nil, fmt.Errorf("ZAP already has an enabled upstream proxy")
	}
	prior, err := call("/JSON/network/view/getHttpProxy/", url.Values{})
	if err != nil {
		return nil, err
	}
	proxy, ok := prior["getHttpProxy"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("ZAP proxy snapshot unavailable")
	}
	auth, err := call("/JSON/network/view/isHttpProxyAuthEnabled/", url.Values{})
	if err != nil {
		return nil, err
	}
	authState := valueString(auth, "isHttpProxyAuthEnabled")
	if authState != "true" && authState != "false" {
		return nil, fmt.Errorf("ZAP proxy auth snapshot unavailable")
	}
	priorJSON, err := json.Marshal(proxy)
	if err != nil {
		return nil, err
	}
	restore := func() error {
		if err := zapPost(cfg, "/JSON/network/action/setHttpProxyEnabled/", url.Values{"enabled": {"false"}}); err != nil {
			return err
		}
		if err := zapPost(cfg, "/OTHER/network/other/setProxy/", url.Values{"proxy": {string(priorJSON)}}); err != nil {
			return err
		}
		return zapPost(cfg, "/JSON/network/action/setHttpProxyAuthEnabled/", url.Values{"enabled": {authState}})
	}
	u, err := url.Parse(gateway.URL)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, err
	}
	for _, step := range []struct {
		path   string
		params url.Values
	}{
		{"/JSON/network/action/setHttpProxy/", url.Values{"host": {u.Hostname()}, "port": {strconv.Itoa(port)}, "username": {gateway.username}, "password": {gateway.password}}},
		{"/JSON/network/action/setHttpProxyAuthEnabled/", url.Values{"enabled": {"true"}}},
		{"/JSON/network/action/setHttpProxyEnabled/", url.Values{"enabled": {"true"}}},
	} {
		if _, err := call(step.path, step.params); err != nil {
			if restoreErr := restore(); restoreErr != nil {
				quarantineZAPService(cfg.ZAPURL, "recording proxy restore failed")
			}
			return nil, fmt.Errorf("install ZAP recording proxy failed")
		}
	}
	return restore, nil
}

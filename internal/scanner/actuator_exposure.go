package scanner

import (
	"context"
	"net/http"
	"strings"
)

// actuatorCatalogVersion is part of the plan fingerprint through the scanner
// registry/tool version input. Keep this catalog small and reviewable.
const actuatorCatalogVersion = "actuator-v1"

type actuatorExposureRunner struct{}

func (actuatorExposureRunner) Name() string { return "actuator" }
func (actuatorExposureRunner) Descriptor() Descriptor {
	return Descriptor{Name: "actuator", Summary: "Bounded read-only Spring Boot Actuator exposure checks", Phase: PhaseWeb, Tracks: []Track{TrackWeb}, Weight: WeightLight}
}

func (actuatorExposureRunner) Run(ctx context.Context, req Request, cfg Config, emit EmitFunc) Run {
	return runExposureCatalog(ctx, req, cfg, emit, "actuator", actuatorCatalogVersion, "Spring Boot Actuator exposure", actuatorCatalog, classifyActuator)
}

// actuatorCatalog probes the Spring Boot Actuator management surface on both the
// 2.x+ /actuator base path and the 1.x root paths. Every probe is a read-only
// GET; the heap/thread dumps are only read up to the shared body cap, never
// fully downloaded.
var actuatorCatalog = []exposureCheck{
	{ID: "actuator-index", Path: "/actuator", Purpose: "Spring Boot Actuator index"},
	{ID: "actuator-env", Path: "/actuator/env", Purpose: "Spring Boot environment endpoint"},
	{ID: "actuator-configprops", Path: "/actuator/configprops", Purpose: "Spring Boot configuration-properties endpoint"},
	{ID: "actuator-health", Path: "/actuator/health", Purpose: "Spring Boot health endpoint"},
	{ID: "actuator-mappings", Path: "/actuator/mappings", Purpose: "Spring Boot request-mappings endpoint"},
	{ID: "actuator-beans", Path: "/actuator/beans", Purpose: "Spring Boot beans endpoint"},
	{ID: "actuator-metrics", Path: "/actuator/metrics", Purpose: "Spring Boot metrics endpoint"},
	{ID: "actuator-loggers", Path: "/actuator/loggers", Purpose: "Spring Boot loggers endpoint"},
	{ID: "actuator-threaddump", Path: "/actuator/threaddump", Purpose: "Spring Boot thread-dump endpoint"},
	{ID: "actuator-heapdump", Path: "/actuator/heapdump", Purpose: "Spring Boot heap-dump endpoint"},
	{ID: "legacy-env", Path: "/env", Purpose: "Spring Boot 1.x environment endpoint"},
	{ID: "legacy-health", Path: "/health", Purpose: "Spring Boot 1.x health endpoint"},
	{ID: "legacy-mappings", Path: "/mappings", Purpose: "Spring Boot 1.x request-mappings endpoint"},
	{ID: "legacy-dump", Path: "/dump", Purpose: "Spring Boot 1.x thread-dump endpoint"},
	{ID: "legacy-trace", Path: "/trace", Purpose: "Spring Boot 1.x HTTP-trace endpoint"},
	{ID: "legacy-heapdump", Path: "/heapdump", Purpose: "Spring Boot 1.x heap-dump endpoint"},
}

// looksLikeActuator distinguishes a genuine Actuator response from any JSON
// endpoint, keeping the management-surface findings from firing on unrelated
// APIs. The Actuator media type or one of its characteristic top-level keys is
// required.
func looksLikeActuator(contentType, lowerBody string) bool {
	if strings.Contains(contentType, "actuator") {
		return true
	}
	for _, key := range []string{"\"_links\"", "\"contexts\"", "\"propertysources\"", "\"activeprofiles\"", "\"loggers\"", "\"measurements\"", "\"names\""} {
		if strings.Contains(lowerBody, key) {
			return true
		}
	}
	return false
}

// classifyActuator judges one probed response. Evidence is left to the shared
// driver's redaction-safe default (status + header fingerprint + classification);
// no response body is ever written to the artifact.
func classifyActuator(check exposureCheck, resp *http.Response, body []byte) exposureVerdict {
	if resp.StatusCode != http.StatusOK {
		return exposureVerdict{}
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	lower := strings.ToLower(string(body))
	isJSON := strings.Contains(ct, "json") || strings.Contains(ct, "actuator") || strings.HasPrefix(strings.TrimSpace(string(body)), "{")
	octet := strings.Contains(ct, "octet-stream") || strings.Contains(ct, "x-java") || strings.Contains(ct, "hprof")
	switch {
	case strings.Contains(check.ID, "heapdump"):
		// A 200 heap dump (binary, or a body that fills the read cap) leaks
		// process memory, which commonly includes credentials and tokens.
		if octet || len(body) >= exposureBodyLimit {
			return exposureVerdict{Classification: "sensitive_artifact_exposed", Severity: "high", Title: "Spring Boot heap dump is publicly downloadable"}
		}
	case strings.Contains(check.ID, "env") || strings.Contains(check.ID, "configprops"):
		if isJSON && (strings.Contains(lower, "propertysources") || strings.Contains(lower, "activeprofiles") || strings.Contains(lower, "contexts")) {
			return exposureVerdict{Classification: "configuration_disclosure", Severity: "high", Title: "Spring Boot configuration/environment endpoint exposed"}
		}
	case strings.Contains(check.ID, "threaddump") || strings.Contains(check.ID, "dump") || strings.Contains(check.ID, "trace"):
		if isJSON && looksLikeActuator(ct, lower) {
			return exposureVerdict{Classification: "internal_disclosure", Severity: "medium", Title: "Spring Boot internal diagnostics endpoint exposed"}
		}
	case strings.Contains(check.ID, "health"):
		if isJSON && strings.Contains(lower, "\"status\"") {
			return exposureVerdict{Classification: "management_surface_exposed", Severity: "low", Title: "Spring Boot health endpoint exposed"}
		}
	case strings.Contains(check.ID, "index"):
		if isJSON && strings.Contains(lower, "_links") && looksLikeActuator(ct, lower) {
			return exposureVerdict{Classification: "management_surface_exposed", Severity: "medium", Title: "Spring Boot Actuator index exposed"}
		}
	default:
		if isJSON && looksLikeActuator(ct, lower) {
			return exposureVerdict{Classification: "management_surface_exposed", Severity: "medium", Title: "Spring Boot Actuator management endpoint exposed"}
		}
	}
	return exposureVerdict{}
}

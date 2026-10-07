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
# Set STAGED_SUITE=recovery to run the application restart/recovery suite
# (graceful restarts and a hard kill mid-run) instead of the default suite.
#
# Set STAGED_SUITE=identities to run two supplied identities (protected markers,
# an anonymous control, role separation) and check that no synthetic credential
# appears in any API response, saved artifact, output stream or the report.
#
# Set STAGED_SUITE=ui to seed a base assessment through the API and then drive
# the dashboard in a real browser (runtime/ui-acceptance, playwright-core with the
# image's own Chromium and a Node binary copied from a pinned Node image).
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
data_volume="$prefix-data"
cleanup() {
  docker rm -f "$app_container" "$lab_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$data_volume" >/dev/null 2>&1 || true
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
docker volume create "$data_volume" >/dev/null
docker run -d --name "$lab_container" --network "$network" \
  --network-alias lab-primary --network-alias lab-secondary --network-alias lab-alias \
  --entrypoint /lab/stagedlab -v "$result_dir/stagedlab:/lab/stagedlab:ro" "$image" >/dev/null

app_mounts=()
if [[ -n "$app_binary" ]]; then
  app_mounts=(-v "$(cd "$(dirname "$app_binary")" && pwd)/$(basename "$app_binary"):/usr/local/bin/xalgorix:ro")
fi
docker run -d --name "$app_container" --network "$network" --network-alias app --network-alias dashboard \
  -e XALGORIX_UNIFIED_WORKFLOW=1 -e XALGORIX_ALLOW_LOCAL_TARGETS=true \
  -e XALGORIX_USERNAME=acceptance -e XALGORIX_PASSWORD="$password" \
  -e XALGORIX_DATA_DIR=/data -e XALGORIX_CREDENTIAL_KEY_FILE=/run/key/credential.key \
  -e XALGORIX_BIND=0.0.0.0 \
  -v "$data_volume:/data" -v "$result_dir/credential.key:/run/key/credential.key:ro" \
  ${app_mounts[@]+"${app_mounts[@]}"} "$image" --web --port 8888 >/dev/null

run_phase() {
  local phase=$1
  docker run --rm --network "$network" \
    -e STAGED_APP=http://app:8888 -e STAGED_USER=acceptance -e STAGED_PASSWORD="$password" \
    -e STAGED_PHASE="$phase" -e STAGED_RESULT="/out/result-$phase.json" -e STAGED_STATE=/out/state.json \
    -e STAGED_REUSE_SCAN="${STAGED_REUSE_SCAN:-}" -e STAGED_SCAN_TIMEOUT="${STAGED_SCAN_TIMEOUT:-2400}" \
    -v "$repo_root/runtime/staged_acceptance.py:/staged_acceptance.py:ro" -v "$result_dir:/out" \
    --entrypoint python3 "$image" /staged_acceptance.py
}
# Real process restarts of the application container. The data volume, lab and
# network persist; only the application process is interrupted.
restart_graceful() { echo "--- restarting the application process (SIGTERM)"; docker restart "$app_container" >/dev/null; }
restart_after_kill() { echo "--- killing the application process (SIGKILL)"; docker kill "$app_container" >/dev/null; docker start "$app_container" >/dev/null; }

run_ui_phase() {
  local node_image=node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
  local node_container
  node_container=$(docker create "$node_image")
  docker cp "$node_container:/usr/local/bin/node" "$result_dir/node" >/dev/null
  docker rm "$node_container" >/dev/null
  (cd "$repo_root/runtime/ui-acceptance" && npm ci --no-audit --no-fund >/dev/null)
  docker run --rm --network "$network" --shm-size=512m \
    -e UI_BASE=http://dashboard:8888 -e UI_USER=acceptance -e UI_PASSWORD="$password" \
    -e UI_STATE=/out/state.json -e UI_RESULT=/out/result-ui.json \
    -v "$repo_root/runtime/ui-acceptance:/ui:ro" -v "$result_dir/node:/usr/local/bin/node:ro" -v "$result_dir:/out" \
    -w /ui --entrypoint node "$image" staged_ui_acceptance.mjs
}

status=0
if [[ "${STAGED_SUITE:-}" == ui ]]; then
  run_phase recovery-base || status=$?
  if [[ $status -eq 0 ]]; then run_ui_phase || status=$?; fi
elif [[ "${STAGED_SUITE:-}" == identities ]]; then
  run_phase identities || status=$?
elif [[ "${STAGED_SUITE:-}" == recovery ]]; then
  run_phase recovery-base || status=$?
  if [[ $status -eq 0 ]]; then restart_graceful; run_phase recovery-pending || status=$?; fi
  if [[ $status -eq 0 ]]; then restart_graceful; run_phase recovery-accepted || status=$?; fi
  if [[ $status -eq 0 ]]; then restart_after_kill; run_phase recovery-midrun || status=$?; fi
  if [[ $status -eq 0 ]]; then run_phase recovery-stop || status=$?; fi
  if [[ $status -eq 0 ]]; then restart_graceful; run_phase recovery-after-stop || status=$?; fi
else
  run_phase full || status=$?
fi

docker logs "$app_container" > "$result_dir/app.log" 2>&1 || true
docker logs "$lab_container" > "$result_dir/lab.log" 2>&1 || true
echo "Results and logs: $result_dir"
if [[ $status -ne 0 ]]; then
  echo 'Staged acceptance FAILED; see result.json' >&2
  exit "$status"
fi
echo 'Staged acceptance passed; this does not enable the rollout flag'

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
# Set STAGED_SUITE=recovery-auth to hard-kill the application during an authenticated
# crawl and verify the resumed assessment logs in again instead of reusing sessions.
#
# Set STAGED_SUITE=recovery-write to hard-kill the application while an approved
# form campaign is in flight and verify that nothing is replayed after the restart.
#
# Set STAGED_SUITE=failures to inject failures: truncated Nuclei JSON, an empty
# Wapiti report, a missing Dalfox binary, no ZAP, and session expiry mid-run, and
# check that each is reported as a failure or gap and never as a clean result.
#
# Set STAGED_SUITE=api to import OpenAPI and GraphQL definitions with supplied inputs,
# run an exactly-once write with declared cleanup, and compare two identities'
# access to a resource fixture.
#
# Set STAGED_SUITE=scanners to run Nuclei (signed deterministic template), Wapiti
# including an approved bounded form POST campaign, Dalfox and a dedicated ZAP
# daemon in one assessment (STAGED_ZAP_TIMEOUT caps ZAP in seconds).
#
# Set STAGED_SUITE=identities to run two supplied identities (protected markers,
# an anonymous control, role separation) and check that no synthetic credential
# appears in any API response, saved artifact, output stream or the report.
#
# Set STAGED_SUITE=services to run one shared token login across four lab
# microservices with real Nuclei and a dedicated ZAP daemon, and check that the
# token reaches every bound service and never the unbound one.
#
# Set STAGED_SUITE=writefuzz to run opt-in API write fuzzing (Schemathesis sends
# generated POST/PUT/PATCH/DELETE) against a disposable JSON write surface and
# check it stays inside scope, skips the excluded route, and is blocked without
# the test-environment declaration.
#
# Set STAGED_SUITE=registry to push a sample image (STAGED_REGISTRY_SOURCE,
# default redis:8-alpine, must already exist locally) into a disposable
# basic-auth registry and check that Trivy pulls it only with the bound
# registry login. This suite's network is not internal: Trivy downloads its
# vulnerability database exactly as in production. The image is exported with
# docker save and pushed from inside the network (runtime/registry_push.py), so
# the operator's Docker daemon never logs in to or pushes to anything.
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
zap_container="$prefix-zap"
registry_container="$prefix-registry"
data_volume="$prefix-data"
cleanup() {
  docker rm -f "$app_container" "$lab_container" "$zap_container" "$registry_container" >/dev/null 2>&1 || true
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

if [[ "${STAGED_SUITE:-}" == registry ]]; then
  docker network create "$network" >/dev/null
else
  docker network create --internal "$network" >/dev/null
fi
docker volume create "$data_volume" >/dev/null
docker run -d --name "$lab_container" --network "$network" \
  --network-alias lab-primary --network-alias lab-secondary --network-alias lab-alias \
  --network-alias lab-svc-auth --network-alias lab-svc-orders --network-alias lab-svc-reports --network-alias lab-svc-stray \
  --entrypoint /lab/stagedlab -v "$result_dir/stagedlab:/lab/stagedlab:ro" "$image" >/dev/null

# The scanners suite adds a signed deterministic Nuclei template (prepared offline)
# and a dedicated disposable ZAP daemon on the same internal network.
scanner_env=()
if [[ "${STAGED_SUITE:-}" == scanners || "${STAGED_SUITE:-}" == services ]]; then
  mkdir -p "$result_dir/nuclei"
  docker run --rm --network none \
    -v "$repo_root/runtime/staged-nuclei-prepare.sh:/prep.sh:ro" -v "$result_dir/nuclei:/nuclei" \
    --entrypoint sh "$image" /prep.sh /nuclei
  zap_key=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
  docker run -d --name "$zap_container" --network "$network" --network-alias zap --memory 2500m \
    ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2 \
    zap.sh -Xmx1g -silent -daemon -host 0.0.0.0 -port 8080 \
    -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
    -config "api.key=$zap_key" -config api.filexfer=true >/dev/null
  docker run --rm --network "$network" -e ZAP_KEY="$zap_key" --entrypoint python3 "$image" -c '
import os, time, urllib.request
url = "http://zap:8080/JSON/core/view/version/?apikey=" + os.environ["ZAP_KEY"]
for _ in range(120):
    try:
        urllib.request.urlopen(url, timeout=2).read()
        break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("Disposable ZAP did not become ready")
'
  scanner_env=(-e XALGORIX_NUCLEI_TEMPLATES_DIR=/nuclei/templates -e "NUCLEI_USER_CERTIFICATE=$(cat "$result_dir/nuclei/certificate.pem")"
    -e XALGORIX_ZAP_URL=http://zap:8080 -e "XALGORIX_ZAP_API_KEY=$zap_key" -e XALGORIX_ZAP_DEDICATED=true
    -e XALGORIX_SCANNER_GATEWAY_HOST=dashboard -e XALGORIX_ZAP_TIMEOUT_SECONDS="${STAGED_ZAP_TIMEOUT:-900}"
    -v "$result_dir/nuclei:/nuclei:ro")
fi

# The failures suite replaces scanners with ones that fail in realistic ways:
# truncated JSON, an empty report and a missing binary; ZAP stays unconfigured.
if [[ "${STAGED_SUITE:-}" == failures ]]; then
  scanner_env=(-e XALGORIX_NUCLEI_PATH=/fakes/nuclei-malformed -e XALGORIX_WAPITI_PATH=/fakes/wapiti-empty
    -e XALGORIX_DALFOX_PATH=/nonexistent/dalfox -v "$repo_root/runtime/staged-fakes:/fakes:ro")
fi

phase_env=()
if [[ "${STAGED_SUITE:-}" == registry ]]; then
  registry_user=staged-reader
  registry_password=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
  docker run --rm --network none -e STAGED_REGISTRY_PASSWORD="$registry_password" \
    --entrypoint /lab/stagedlab -v "$result_dir/stagedlab:/lab/stagedlab:ro" "$image" -htpasswd "$registry_user" > "$result_dir/htpasswd"
  chmod 0644 "$result_dir/htpasswd"
  docker run -d --name "$registry_container" --network "$network" --network-alias registry \
    -e REGISTRY_AUTH=htpasswd -e REGISTRY_AUTH_HTPASSWD_REALM=staged -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
    -v "$result_dir/htpasswd:/auth/htpasswd:ro" \
    registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 >/dev/null
  # The image is exported locally and pushed from inside the network, so the
  # operator's Docker daemon never logs in to or pushes to anything.
  docker save --platform "linux/$arch" -o "$result_dir/sample-image.tar" "${STAGED_REGISTRY_SOURCE:-redis:8-alpine}" 2>/dev/null \
    || docker save -o "$result_dir/sample-image.tar" "${STAGED_REGISTRY_SOURCE:-redis:8-alpine}"
  chmod 0644 "$result_dir/sample-image.tar"
  docker run --rm --network "$network" -e REGISTRY_USER="$registry_user" -e REGISTRY_PASSWORD="$registry_password" \
    -v "$repo_root/runtime/registry_push.py:/registry_push.py:ro" -v "$result_dir/sample-image.tar:/sample.tar:ro" \
    --entrypoint python3 "$image" -c '
import subprocess, sys, time, urllib.request, urllib.error
for _ in range(60):
    try:
        urllib.request.urlopen("http://registry:5000/v2/", timeout=2)
        break
    except urllib.error.HTTPError:
        break  # 401 means the registry is up and enforcing auth
    except Exception:
        time.sleep(1)
sys.exit(subprocess.call([sys.executable, "/registry_push.py", "/sample.tar", "registry:5000", "staged/sample", "1"]))
'
  scanner_env=(-e TRIVY_INSECURE=true)
  phase_env=(-e STAGED_REGISTRY_IMAGE=registry:5000/staged/sample:1 -e STAGED_REGISTRY_HOST=registry:5000
    -e STAGED_REGISTRY_USER="$registry_user" -e STAGED_REGISTRY_PASSWORD="$registry_password")
fi

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
  ${scanner_env[@]+"${scanner_env[@]}"} ${app_mounts[@]+"${app_mounts[@]}"} "$image" --web --port 8888 >/dev/null

run_phase() {
  local phase=$1
  docker run --rm --network "$network" \
    -e STAGED_APP=http://app:8888 -e STAGED_USER=acceptance -e STAGED_PASSWORD="$password" \
    -e STAGED_PHASE="$phase" -e STAGED_RESULT="/out/result-$phase.json" -e STAGED_STATE=/out/state.json \
    -e STAGED_REUSE_SCAN="${STAGED_REUSE_SCAN:-}" -e STAGED_SCAN_TIMEOUT="${STAGED_SCAN_TIMEOUT:-2400}" \
    ${phase_env[@]+"${phase_env[@]}"} \
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
elif [[ "${STAGED_SUITE:-}" == api ]]; then
  run_phase api || status=$?
elif [[ "${STAGED_SUITE:-}" == scanners ]]; then
  run_phase scanners || status=$?
elif [[ "${STAGED_SUITE:-}" == services ]]; then
  run_phase services || status=$?
elif [[ "${STAGED_SUITE:-}" == registry ]]; then
  run_phase registry || status=$?
elif [[ "${STAGED_SUITE:-}" == writefuzz ]]; then
  run_phase writefuzz || status=$?
elif [[ "${STAGED_SUITE:-}" == recovery-auth ]]; then
  run_phase auth-start || status=$?
  if [[ $status -eq 0 ]]; then restart_after_kill; run_phase auth-after-kill || status=$?; fi
elif [[ "${STAGED_SUITE:-}" == recovery-write ]]; then
  run_phase write-start || status=$?
  if [[ $status -eq 0 ]]; then restart_after_kill; run_phase write-after-kill || status=$?; fi
elif [[ "${STAGED_SUITE:-}" == failures ]]; then
  run_phase failures || status=$?
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

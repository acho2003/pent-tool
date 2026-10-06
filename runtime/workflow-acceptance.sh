#!/usr/bin/env bash
# Run only disposable local fixtures. Never attach to application services.
set -euo pipefail
if [[ $# != 3 ]]; then
  echo 'Usage: runtime/workflow-acceptance.sh IMAGE SCANNER_TEST_BINARY WEB_TEST_BINARY' >&2
  exit 2
fi
runtime_image=$1
scanner_binary=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
web_binary=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ -f "$scanner_binary" && -f "$web_binary" ]] || { echo 'Missing compiled test binary' >&2; exit 2; }
fixture_prefix="xalgorix-acceptance-$$"
fixture_network="$fixture_prefix-network"
fixture_zap="$fixture_prefix-zap"
fixture_worker="$fixture_prefix-worker"
cleanup() {
  docker rm -f "$fixture_worker" "$fixture_zap" >/dev/null 2>&1 || true
  docker network rm "$fixture_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo 'Running offline browser, request routing, cancellation and process recovery fixtures'
docker run --rm --name "$fixture_worker" --network none \
  --entrypoint /tmp/scanner.test \
  -e XALGORIX_TEST_CHROMIUM=/usr/bin/chromium \
  -e XALGORIX_TEST_WAPITI=1 -e XALGORIX_TEST_WAPITI_POST=1 \
  -e XALGORIX_TEST_NUCLEI=1 -e XALGORIX_TEST_DALFOX=1 \
  -v "$scanner_binary:/tmp/scanner.test:ro" "$runtime_image" \
  -test.timeout 10m -test.v \
  -test.run '^Test(BrowserRuntime|WapitiRuntime|NucleiRuntime|DalfoxRuntime|ExpandedWorkflowRecoversAfterWorkerProcessIsKilled)'

echo 'Running offline web persistence, approval, evidence and compatibility race suite'
docker run --rm --name "$fixture_worker" --network none \
  --entrypoint /tmp/web.test -w /src/internal/web \
  -v "$repo_root:/src:ro" -v "$web_binary:/tmp/web.test:ro" \
  "$runtime_image" -test.timeout 5m

echo 'Starting isolated pinned ZAP for request and supplemental discovery fixtures'
docker network create --internal "$fixture_network" >/dev/null
docker run -d --name "$fixture_zap" --network "$fixture_network" --network-alias zap \
  --memory 1200m -e JAVA_OPTS=-Xmx512m \
  ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2 \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.key=workflow-fixture -config 'api.addrs.addr.name=.*' \
  -config api.addrs.addr.regex=true -config api.filexfer=true >/dev/null
docker run --rm --name "$fixture_worker" --network "$fixture_network" \
  --entrypoint python3 "$runtime_image" -c '
import time, urllib.request
for attempt in range(60):
    try:
        urllib.request.urlopen("http://zap:8080/JSON/core/view/version/?apikey=workflow-fixture", timeout=2).read()
        break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("Disposable ZAP did not become ready")
'
docker run --rm --name "$fixture_worker" --network "$fixture_network" --network-alias fixture \
  --entrypoint /tmp/scanner.test \
  -e XALGORIX_TEST_ZAP=http://zap:8080 -e XALGORIX_SCANNER_GATEWAY_HOST=fixture \
  -v "$scanner_binary:/tmp/scanner.test:ro" "$runtime_image" \
  -test.timeout 5m -test.run '^TestZAPRuntime' -test.v
echo 'Native workflow fixture acceptance passed; this does not enable the rollout flag'

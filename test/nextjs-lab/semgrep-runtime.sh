#!/bin/sh
# Test-only adapter: mount only the native runner's private bounded snapshot.
set -eu
rules=""
previous=""
for argument in "$@"; do
  if [ "$previous" = --config ]; then rules="$argument"; fi
  previous="$argument"
done
workspace=$(dirname "$rules")
case "$(basename "$workspace")" in
  xalgorix-nextjs-sast-*) ;;
  *) echo "expected a private Next.js source-analysis workspace" >&2; exit 2 ;;
esac
[ -f "$rules" ] && [ -d "$workspace/source" ]
exec docker run --rm --pull never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 --memory 1g --cpus 2 \
  --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,mode=1777 \
  -v "$workspace:$workspace:rw" -w "$workspace/source" \
  -e SEMGREP_SEND_METRICS=off -e SEMGREP_ENABLE_VERSION_CHECK=0 \
  -e "SEMGREP_SETTINGS_FILE=$workspace/settings.yml" \
  -e "SEMGREP_LOG_FILE=$workspace/semgrep.log" \
  --entrypoint /opt/venvs/semgrep/bin/semgrep \
  "${XALGORIX_SEMGREP_IMAGE:-xalgorix:local}" "$@"

#!/usr/bin/env bash
# Fetch the official pinned Wazuh single-node Compose bundle without starting it.
set -euo pipefail
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Run this on the dedicated Linux Wazuh host." >&2
  exit 1
fi
if [[ $# -ne 1 || -z "$1" ]]; then
  echo "Usage: bash setup.sh /absolute/path/to/wazuh-stack" >&2
  exit 1
fi
destination="$1"
if [[ "$destination" != /* || -e "$destination" ]]; then
  echo "Destination must be an unused absolute path." >&2
  exit 1
fi
git clone --depth 1 --branch v4.14.8 https://github.com/wazuh/wazuh-docker.git "$destination"
echo "Pinned Wazuh Compose bundle fetched to $destination/single-node"
echo "Generate certificates and rotate every upstream default password before running preflight.sh or starting the stack."

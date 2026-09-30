#!/usr/bin/env bash
# Run from the pinned wazuh-docker/single-node directory before first start.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Wazuh deployment requires a Linux host for this Xalgorix package." >&2
  exit 1
fi
if [[ ! -f docker-compose.yml || ! -f config/wazuh_indexer/internal_users.yml ]]; then
  echo "Run from wazuh-docker/single-node at tag v4.14.8." >&2
  exit 1
fi
if [[ "$(git describe --tags --exact-match 2>/dev/null || true)" != "v4.14.8" ]]; then
  echo "Use the pinned Wazuh Docker tag v4.14.8." >&2
  exit 1
fi
if [[ "$(nproc)" -lt 4 ]]; then echo "Need at least 4 CPU cores." >&2; exit 1; fi
if [[ "$(awk '/MemTotal:/ {print int($2/1024/1024)}' /proc/meminfo)" -lt 8 ]]; then echo "Need at least 8 GiB RAM." >&2; exit 1; fi
if [[ "$(df -Pk . | awk 'NR==2 {print int($4/1024/1024)}')" -lt 50 ]]; then echo "Need at least 50 GiB free disk." >&2; exit 1; fi
if [[ "$(sysctl -n vm.max_map_count)" -lt 262144 ]]; then echo "Set vm.max_map_count to at least 262144." >&2; exit 1; fi
if grep -Eq 'SecretPassword|MyS3cr37P450r|DASHBOARD_PASSWORD=kibanaserver' docker-compose.yml config/wazuh_dashboard/wazuh.yml; then
  echo "Default Wazuh passwords remain in Compose/dashboard configuration. Rotate them before startup." >&2
  exit 1
fi
if git -C .. diff --quiet v4.14.8 -- single-node/config/wazuh_indexer/internal_users.yml; then
  echo "Indexer internal_users.yml still contains upstream default hashes. Rotate all users before startup." >&2
  exit 1
fi
for cert in root-ca.pem wazuh.indexer.pem wazuh.indexer-key.pem wazuh.manager.pem wazuh.manager-key.pem wazuh.dashboard.pem wazuh.dashboard-key.pem; do
  if [[ ! -s "config/wazuh_indexer_ssl_certs/$cert" ]]; then echo "Missing certificate: $cert" >&2; exit 1; fi
done
docker compose config --quiet
echo "Preflight passed. Ensure API and indexer ports are reachable only over your private network/VPN."

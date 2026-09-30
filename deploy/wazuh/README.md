# Optional Wazuh deployment for Xalgorix

This package uses Wazuh's **pinned v4.14.8 single-node Docker stack** on a dedicated Linux host. It is not included in Xalgorix's default `docker-compose.yml`, so a scanner workstation does not silently become a SIEM server. Wazuh retains and indexes events; Xalgorix queries its APIs.

## Prepare the Linux host

- Minimum for the first 25 agents: 4 cores, 8 GiB RAM, and 50 GiB free disk. Reserve more disk for longer alert retention. Set `vm.max_map_count=262144` persistently on the host.
- Install current Docker Engine and Compose. Use a private network or VPN between Xalgorix and this host. Agents must reach the manager on TCP 1514 and TCP 1515. Restrict API port 55000, indexer port 9200, and dashboard HTTPS to administrators and Xalgorix; never expose them to the public internet.
- Run this package's `setup.sh /absolute/path/to/wazuh-stack` on the Linux host. It fetches the official [Wazuh Docker repository](https://github.com/wazuh/wazuh-docker) at tag `v4.14.8` without starting it. Use its `single-node/` directory. Keep this checkout outside the Xalgorix scan-data directory.
- Generate the [official TLS certificates](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#self-signed-certificates) or install trusted certificates for the manager, indexer, and dashboard. Import the issuing CA PEM in Xalgorix's Monitoring → Connection screen. Do not disable certificate verification.
- **Before starting any Wazuh service**, replace the upstream example passwords in Compose, dashboard config, and all default indexer user hashes. Follow Wazuh's [Docker password-rotation instructions](https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html). Create dedicated, least-privilege API/indexer users for Xalgorix where practical. This integration does not ship or accept default credentials.
- Run `preflight.sh` from this package while your working directory is the official `single-node/` directory. It rejects known defaults, missing certificates, insufficient host capacity, and an invalid Compose file. Then start the official stack with `docker compose up -d` and check all three components are healthy.

In Xalgorix, go to **Monitoring → Connection**, enter HTTPS manager and indexer API URLs, usernames and passwords, the CA PEM, and the hostname/IP that agents should use to reach the manager. The status badges independently verify manager and indexer connectivity. The **Add server guide** links to official Linux, Windows, and macOS agent instructions; installation runs on each server, not through Xalgorix.

## Operations

- Configure Wazuh index retention and disk alerts for your environment. The 50 GiB minimum is capacity to start, not a guarantee of a particular retention period.
- Back up the Wazuh indexer data, manager configuration/agent keys, API configuration, dashboard configuration, TLS certificate material, and your customized Compose/config files. Restore the complete compatible set and test on a separate host; backing up only Xalgorix data does **not** preserve SIEM history.
- For upgrades, follow the [Wazuh Docker upgrade guide](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html). Back up first, review release notes and API compatibility, update the pinned checkout and images together, and rerun preflight before returning monitoring to service. Xalgorix assessments remain usable if Wazuh is down.
- Active-response commands are disabled in Xalgorix until their exact names are allowlisted in Monitoring → Connection. Commands must already be configured in Wazuh. Grant the Xalgorix manager API user only the needed `active-response:command` permission and agent scope. Each Xalgorix submission requires selecting one agent and typing its ID; submissions and outcomes are appended to `monitoring/active-response-audit.jsonl` in Xalgorix's data directory.

For agent connectivity and enrollment issues, confirm DNS, firewall rules on 1514/1515, the manager's enrollment service, and the agent's own logs. For an empty alerts view, check indexer health, Filebeat forwarding, Wazuh alert indices, and the indexer user's read permissions.

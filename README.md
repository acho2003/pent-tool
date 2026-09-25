# Xalgorix

Xalgorix is a self-hosted deterministic security-scanner pipeline. It runs established scanners in a fixed order and uses AI only after scanning to generate a source-traceable report.

## Execution model

Each scan runs fixed phases:

1. **Recon** — Subfinder enumerates subdomains (skipped for a bare host or URL), httpx keeps the live hosts, and Nmap records open ports and services per host. Each live host becomes a *host scope*. A target with nothing to expand (for example `localhost:3000`) is scanned as a single host.
2. **Classify** — from recon evidence alone, each host gets the `web` track (a live HTTP(S) URL, TLS, or an open 80/443/8080/8443 or HTTP-like service) and/or the `server` track (any other open port). A host with no recon evidence is scanned on both tracks.
3. **Scan** — per host: Nuclei, OWASP ZAP, and testssl.sh on the web track; OpenVAS/Greenbone and Vuls on the server track.
4. **Source code** — once per scan, on a single *source scope*: Trivy, Semgrep, Gitleaks, and OSV-Scanner. Source comes from `--source` (a local directory, or a git repository cloned into the scan directory) or from a git-URL target. With no source, these tools record `not_applicable`.

Scanners run on a bounded worker pool (`XALGORIX_MAX_WORKERS`, default 3). The heavy tools, ZAP and OpenVAS, never run at the same time.

Every applicable tool records exactly one terminal status per scope. Every scope×tool the classifier deemed inapplicable is recorded `not_applicable` or `skipped`, so the report still accounts for all of them. Recon, target classification, tool selection, and command construction are deterministic; AI runs only after all scanning completes.

A scanner failure is recorded and other scanners continue. Cancelling a scan stops the active scanners and marks the remaining attempts cancelled. Completed attempts and their checksums are reused during restart recovery, keyed by (scope, scanner).

AI does not validate targets, discover subdomains, select tools, construct commands, change scan depth, verify findings, calculate status, or generate live output. During execution the dashboard displays native scanner stdout and stderr only.

After all attempts reach terminal states, Xalgorix parses each tool's native output (Nuclei JSONL, ZAP JSON, testssl JSON, Greenbone XML, Vuls JSON, Nmap XML, Trivy, Semgrep, Gitleaks, and OSV-Scanner JSON) into a private canonical input. When different scanners report the same CVE on the same scope, the report shows one finding that lists every source and keeps each source's evidence reference. Report AI may explain, classify, and recommend remediation for those records. Output records with unknown source IDs are rejected. If Report AI is absent or fails, Xalgorix immediately creates a deterministic fallback report.

The report groups findings by scope (each host, then the source code), shows each host's classifier tracks, and opens with a scan-coverage section: a recon summary (hosts discovered, open ports, detected services) and the terminal status of every tool on every scope.

Findings are labelled scanner-reported. Xalgorix does not claim independent exploitation or verification.

## Quick start

Build from source:

```bash
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
make build
./build/xalgorix --web
```

Open `http://127.0.0.1:9137`.

To start the full local scanner stack (including internal ZAP and Greenbone),
build the checked-out source for your Docker architecture:

```bash
docker compose up -d --build
```

On Apple Silicon this avoids the older `xalgord/xalgorix:latest` release image,
which does not provide an arm64 manifest. The first Greenbone startup downloads
and initializes persistent vulnerability feeds, so it can take a while before
the scanner is ready.

A Report AI key is optional. Scanning and fallback reports work without one. Configure a report provider under Settings → Report AI.

CLI examples:

```bash
xalgorix --target https://example.com
xalgorix --target example.com --vuls-ssh-host prod-web
xalgorix --source ./my-app --artifact-kind filesystem
xalgorix --source https://github.com/example/app.git --artifact-kind repository
```

## Scanner inputs

| Scanner | Scope | Input |
|---|---|---|
| Subfinder, httpx, Nmap | Recon | Submitted target; per-host Nmap on each live host |
| Nuclei | Host (web) | Host or live URL |
| ZAP | Host (web) | Deterministically normalized HTTP/HTTPS URL |
| testssl.sh | Host (web) | Host with TLS |
| OpenVAS | Host (server) | Host |
| Vuls | Host (server) | Optional operator-managed SSH host alias |
| Trivy, Semgrep, Gitleaks, OSV-Scanner | Source | Resolved source directory |

## Selecting scanners

By default every scan runs the whole pipeline. To run a subset, tick the scanners in
the dashboard's New scan form, send `"scanners": ["nuclei", "zap"]` to
`POST /api/scan`, or pass `--scanners nuclei,zap` on the CLI. An unknown name is
rejected; order and duplicates do not matter.

A deselected scanner is not omitted from the scan — it is recorded with the
terminal status `skipped` and the reason `not selected for this scan`, so every
scan still accounts for every scope×tool and the report shows what was not attempted.
That is distinct from `not_applicable`, which means a selected scanner had
nothing to work with (no URL, no source, no SSH alias, or a scope outside the tool's track).

Supported Trivy artifact kinds are `filesystem`, `repository`, `image`, and `sbom`. Vuls aliases refer to the operator's SSH configuration. SSH private material is never returned by the API or written to scan records.

Wildcard mode uses deterministic subdomain discovery and normalization before running the full pipeline for each discovered target.

## Native and container configuration

Native installations use configured binary paths and external ZAP/GMP endpoints. Xalgorix does not install tools at scan time. Missing binaries and unavailable services become explicit scanner failures.

Key environment variables:

| Variable | Default | Purpose |
|---|---:|---|
| `XALGORIX_NUCLEI_PATH` | `nuclei` | Nuclei executable |
| `XALGORIX_TRIVY_PATH` | `trivy` | Trivy executable |
| `XALGORIX_VULS_PATH` | `vuls` | Vuls executable |
| `XALGORIX_VULS_SSH_CONFIG` | `~/.ssh/config` | Operator-managed SSH configuration used to resolve Vuls aliases |
| `XALGORIX_SUBFINDER_PATH` | `subfinder` | Subfinder executable (recon) |
| `XALGORIX_HTTPX_PATH` | `httpx` | httpx executable (recon) |
| `XALGORIX_NMAP_PATH` | `nmap` | Nmap executable (recon) |
| `XALGORIX_TESTSSL_PATH` | `testssl.sh` | testssl.sh executable |
| `XALGORIX_SEMGREP_PATH` | `semgrep` | Semgrep executable |
| `XALGORIX_GITLEAKS_PATH` | `gitleaks` | Gitleaks executable |
| `XALGORIX_OSV_PATH` | `osv-scanner` | OSV-Scanner executable |
| `XALGORIX_MAX_WORKERS` | `3` | Concurrent scanner limit (ZAP/OpenVAS are additionally serialized) |
| `XALGORIX_ZAP_URL` | empty | Internal ZAP API URL |
| `XALGORIX_ZAP_API_KEY` | empty | ZAP API key |
| `XALGORIX_GVM_HOST` | empty | Greenbone GMP host |
| `XALGORIX_GVM_PORT` | `9390` | Greenbone GMP port (TLS) |
| `XALGORIX_GVM_SOCKET` | empty | Greenbone GMP UNIX socket; takes precedence over host/port |
| `XALGORIX_GVM_USERNAME` | empty | GMP username |
| `XALGORIX_GVM_PASSWORD` | empty | GMP password |
| `XALGORIX_SCANNER_MAX_OUTPUT_BYTES` | `104857600` | Per-scanner raw output limit |
| `XALGORIX_<TOOL>_TIMEOUT_SECONDS` | per tool | Per-tool timeout, e.g. `XALGORIX_NMAP_TIMEOUT_SECONDS` (1800), `XALGORIX_SEMGREP_TIMEOUT_SECONDS` (1800), `XALGORIX_GITLEAKS_TIMEOUT_SECONDS` (900), `XALGORIX_OSV_TIMEOUT_SECONDS` (900) |
| `XALGORIX_LLM` | empty | Optional Report AI model |
| `XALGORIX_API_KEY` | empty | Optional Report AI key |
| `XALGORIX_API_BASE` | empty | Optional Report AI endpoint |

Nuclei, Trivy, Vuls, Subfinder, httpx, Nmap, testssl.sh, Semgrep, Gitleaks, and OSV-Scanner are expected in the Xalgorix runtime image. ZAP and Greenbone run as authenticated internal services with persistent state and feeds.

## API

Core v2 endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Start a deterministic scan |
| `GET` | `/api/scanners/status` | Scanner health/configuration |
| `GET` | `/api/scans/:id/output/:scanner/:stream` | Read paged/tail raw output |
| `GET` | `/api/scans/:id/:scanner/artifact` | Download a native artifact |
| `GET` | `/api/report/:id` | Download the generated PDF |
| `POST` | `/api/reports/:id/regenerate` | Regenerate from immutable artifacts |

Example request:

```json
{
  "targets": ["https://example.com"],
  "scan_mode": "single",
  "target_auth": "Authorization: Bearer …",
  "artifact": {
    "kind": "repository",
    "ref": "https://github.com/example/app.git"
  },
  "vuls_ssh_host": "prod-web",
  "scanners": ["nuclei", "zap"],
  "company_name": "Example Ltd"
}
```

The legacy `dast` mode is accepted as an alias for `single`. Legacy scan records and their existing reports remain readable.

## Persistence

Schema-v2 records contain a `scanner_runs` collection with scanner name, scope (`recon:<target>`, `host:<host>`, or `source:main`), target, terminal status, timestamps, exit code, reason, output paths, checksum, and truncation state. Large output is not embedded in `scan.json`; stdout, stderr, and native artifacts are append-only files with deterministic credential redaction.

Resume keys on the (scope, scanner) pair. A record written before scopes existed has an empty scope and is treated as the single implicit host scope (`host:<target>`), so older records resume and report unchanged. Recon's discovered host set, with per-host evidence, is persisted at `scanner-output/recon-scopes.json`.

`report.json` records source run checksums, prompt version, provider/model when used, generation mode, timestamp, parse errors, the per-scope coverage list and recon summary, and validated report findings (each with its scope and, for merged findings, every contributing source).

## Safety

Use Xalgorix only on systems you own or have explicit authorization to test. The fixed pipeline can perform active scanning. Scope enforcement and target protections still apply.

## Development

```bash
go test ./...
cd webui && npm run typecheck && npm run build
```

On macOS environments affected by native CPU-detection initialization, use `CGO_ENABLED=0 go test ./...`.

See [LICENSE](LICENSE).

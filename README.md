# Xalgorix

Xalgorix is a self-hosted deterministic security-scanner pipeline. It runs established scanners in a fixed order and uses AI only after scanning to generate a source-traceable report.

## Execution model

Every target receives exactly five scanner statuses in this order:

1. Nuclei
2. OWASP ZAP
3. OpenVAS/Greenbone
4. Trivy
5. Vuls

A scanner failure is recorded and later scanners continue. Cancelling a scan stops the active scanner and marks the remaining attempts cancelled. Completed attempts and their checksums are reused during restart recovery.

AI does not validate targets, discover subdomains, select tools, construct commands, change scan depth, verify findings, calculate status, or generate live output. During execution the dashboard displays native scanner stdout and stderr only.

After all attempts reach terminal states, Xalgorix parses native Nuclei JSONL, ZAP JSON, Greenbone XML, Trivy JSON, and Vuls JSON into a private canonical input. Report AI may deduplicate, explain, classify, and recommend remediation for those records. Output records with unknown source IDs are rejected. If Report AI is absent or fails, Xalgorix immediately creates a deterministic fallback report.

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

| Scanner | Input |
|---|---|
| Nuclei | Submitted host or URL |
| ZAP | Deterministically normalized HTTP/HTTPS URL |
| OpenVAS | Host derived from the submitted target |
| Trivy | Optional `artifact.kind` and `artifact.ref` |
| Vuls | Optional operator-managed SSH host alias |

## Selecting scanners

By default every scan attempts all five. To run a subset, tick the scanners in
the dashboard's New scan form, send `"scanners": ["nuclei", "zap"]` to
`POST /api/scan`, or pass `--scanners nuclei,zap` on the CLI. An unknown name is
rejected; order and duplicates do not matter.

A deselected scanner is not omitted from the scan — it is recorded with the
terminal status `skipped` and the reason `not selected for this scan`, so every
scan still accounts for all five and the report shows what was not attempted.
That is distinct from `not_applicable`, which means a selected scanner had
nothing to work with (no URL, no artifact, no SSH alias).

Supported Trivy artifact kinds are `filesystem`, `repository`, `image`, and `sbom`. Vuls aliases refer to the operator's SSH configuration. SSH private material is never returned by the API or written to scan records.

Wildcard mode uses deterministic subdomain discovery and normalization before running the five-attempt pipeline for each discovered target.

## Native and container configuration

Native installations use configured binary paths and external ZAP/GMP endpoints. Xalgorix does not install tools at scan time. Missing binaries and unavailable services become explicit scanner failures.

Key environment variables:

| Variable | Default | Purpose |
|---|---:|---|
| `XALGORIX_NUCLEI_PATH` | `nuclei` | Nuclei executable |
| `XALGORIX_TRIVY_PATH` | `trivy` | Trivy executable |
| `XALGORIX_VULS_PATH` | `vuls` | Vuls executable |
| `XALGORIX_VULS_SSH_CONFIG` | `~/.ssh/config` | Operator-managed SSH configuration used to resolve Vuls aliases |
| `XALGORIX_ZAP_URL` | empty | Internal ZAP API URL |
| `XALGORIX_ZAP_API_KEY` | empty | ZAP API key |
| `XALGORIX_GVM_HOST` | empty | Greenbone GMP host |
| `XALGORIX_GVM_PORT` | `9390` | Greenbone GMP port (TLS) |
| `XALGORIX_GVM_SOCKET` | empty | Greenbone GMP UNIX socket; takes precedence over host/port |
| `XALGORIX_GVM_USERNAME` | empty | GMP username |
| `XALGORIX_GVM_PASSWORD` | empty | GMP password |
| `XALGORIX_SCANNER_MAX_OUTPUT_BYTES` | `104857600` | Per-scanner raw output limit |
| `XALGORIX_LLM` | empty | Optional Report AI model |
| `XALGORIX_API_KEY` | empty | Optional Report AI key |
| `XALGORIX_API_BASE` | empty | Optional Report AI endpoint |

Nuclei, Trivy, and Vuls are expected in the Xalgorix runtime image. ZAP and Greenbone run as authenticated internal services with persistent state and feeds.

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

Schema-v2 records contain a `scanner_runs` collection with scanner name, target, terminal status, timestamps, exit code, reason, output paths, checksum, and truncation state. Large output is not embedded in `scan.json`; stdout, stderr, and native artifacts are append-only files with deterministic credential redaction.

`report.json` records source run checksums, prompt version, provider/model when used, generation mode, timestamp, parse errors, and validated report findings.

## Safety

Use Xalgorix only on systems you own or have explicit authorization to test. The fixed pipeline can perform active scanning. Scope enforcement and target protections still apply.

## Development

```bash
go test ./...
cd webui && npm run typecheck && npm run build
```

On macOS environments affected by native CPU-detection initialization, use `CGO_ENABLED=0 go test ./...`.

See [LICENSE](LICENSE).

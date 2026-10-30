# Pent Tool

Pent Tool is a self-hosted penetration-testing and security-assessment platform for authorized testing. It combines a web dashboard, assessment planning, native security tools, containerized scanners, Kubernetes exposure checks, and durable assessment artifacts.

Repository: <https://github.com/acho2003/pent-tool>

> The repository is transitioning from its original Xalgorix implementation. Some runtime names, Compose services, binaries, environment variables, and volumes still use `xalgorix`; this README uses the current product name while keeping commands accurate.

## Features

- Web, API, infrastructure, cloud, container, source-code, and Kubernetes assessments.
- Reconnaissance and web testing with Nuclei, ZAP, testssl, Nikto, Dalfox, and Wapiti when enabled.
- Infrastructure checks with OpenVAS, Vuls, Masscan, and Lynis.
- Code and supply-chain checks with Trivy, Semgrep, Gitleaks, and OSV tooling.
- Bounded Kubernetes exposure checks against an explicitly supplied URL.
- [Next.js deep assessments](docs/nextjs-deep-scanning.md) with framework discovery, public exposure checks, controlled access comparisons, approved Server Action campaigns, and controlled cache/URL boundary probes.
- Persistent plans, findings, logs, reports, and raw scanner artifacts.

## Requirements

For Docker: Docker Desktop or Docker Engine with the Compose plugin, Git, at least 4 GB RAM, and network access to authorized targets and required image registries. Native development also needs the Go version in `go.mod`, Node.js/npm for the web UI, scanner binaries required by your assessment types, and PostgreSQL when using the PostgreSQL store outside Compose.

Only test systems you own or are explicitly authorized to assess.

## Quick start with Docker

```bash
git clone https://github.com/acho2003/pent-tool.git
cd pent-tool
mkdir -p secrets
openssl rand -out secrets/xalgorix-credential.key 32
chmod 600 secrets/xalgorix-credential.key
```

Create `.env` with only `KEY=value` entries:

```dotenv
XALGORIX_USERNAME=admin
XALGORIX_PASSWORD=change-this-password
XALGORIX_STORE=postgres
XALGORIX_PG_PASSWORD=change-this-database-password
```

Do not paste YAML such as `dns:` into `.env`. Never commit `.env`, private keys, passwords, or scanner credentials.

Validate and start:

```bash
docker compose config >/dev/null
docker compose up -d --build
docker compose ps
docker compose logs -f xalgorix
```

Open <http://127.0.0.1:9137> and sign in with the configured credentials.

## Common Docker commands

```bash
docker compose build xalgorix
docker compose up -d --no-deps --force-recreate xalgorix
docker compose logs -f xalgorix
docker compose logs -f postgres
docker compose exec postgres pg_isready
docker compose down
```

`docker compose down` preserves volumes. Avoid `docker compose down -v` unless you intentionally want to remove persistent data.

## Native development

The current Makefile still uses the legacy executable name:

```bash
make build
./build/xalgorix --web
make webui-install
make webui
CGO_ENABLED=0 go test ./...
go vet ./...
```

Use `./build/xalgorix --help` and `--version` to inspect the current CLI.

## Assessment workflow

1. Start the application and create an assessment from the dashboard or API.
2. Define the target, scope, and assessment type explicitly.
3. Review the generated plan before execution.
4. Run the assessment and monitor logs and progress.
5. Review findings, evidence, and raw artifacts.
6. Export or archive the report and record remediation notes.

Plans include stable fingerprints so equivalent plans can be compared across runs. Scanner failures are recorded separately from security findings; a failed check must not be interpreted as a clean result.

## Kubernetes exposure checks

`kube-exposure` performs bounded, read-only HTTP checks for common Kubernetes-related exposure indicators against an explicitly supplied URL. It does not require cluster credentials, kubeconfig, a namespace, cloud metadata access, or mutation of the target.

The scanner checks a small catalog of known paths, follows only in-scope redirects up to its configured limit, and records request errors with context. A reachable endpoint or generic HTTP status is not automatically a vulnerability; findings require matching evidence. DNS, routing, TLS, authentication, and upstream failures are execution diagnostics. Run it only against authorized infrastructure. It is not a replacement for an authenticated review such as kube-bench.

## DNS and connectivity troubleshooting

```bash
dig example.internal
docker compose exec xalgorix getent hosts example.internal
```

If the container needs public DNS, configure it under the service in `docker-compose.yml`, not in `.env`:

```yaml
services:
  xalgorix:
    dns:
      - 1.1.1.1
      - 8.8.8.8
```

For private targets, use the organization’s DNS/VPN resolver instead of public resolvers.

## Data, artifacts, and backups

Assessment data is persisted by Compose volumes and the application data directory. Common artifacts are stored under `/data/_assessments` inside the application environment.

```bash
docker compose exec -T postgres pg_dump -U postgres postgres > pent-tool.sql
cp secrets/xalgorix-credential.key ./secure-backup/
```

Treat reports and raw scanner output as sensitive: they may contain URLs, hostnames, headers, source excerpts, credentials accidentally emitted by tools, and infrastructure details.

## Configuration

Common variables in the current runtime are:

| Variable | Purpose |
| --- | --- |
| `XALGORIX_USERNAME` | Dashboard username. |
| `XALGORIX_PASSWORD` | Dashboard password. |
| `XALGORIX_STORE` | Storage backend, commonly `postgres`. |
| `XALGORIX_PG_PASSWORD` | PostgreSQL password used by Compose. |
| `XALGORIX_PG_DSN` | PostgreSQL connection string when configured explicitly. |
| `XALGORIX_CREDENTIAL_KEY_FILE` | Protected credential key path. |
| `XALGORIX_PORT` | Web/API port when supported. |

Use the checked-in Compose file and source as authoritative; the `XALGORIX_` prefix remains for compatibility during the rename.

## API and diagnosis

```bash
curl -i http://127.0.0.1:9137/
docker compose ps
docker compose logs --tail=200 xalgorix
```

The running service and current source are authoritative for available routes and API details.

## Security guidance

- Use strong, unique credentials and rotate them after testing.
- Keep the dashboard on a trusted interface or behind an authenticated reverse proxy.
- Do not expose PostgreSQL publicly.
- Use least privilege for scanner processes.
- Keep the credential key and database backups separate from source control.
- Review every target and scope before launching an assessment.
- Preserve raw evidence with scanner, timestamp, request context, and failure state.

## Documentation and license

- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [License](LICENSE)

See [LICENSE](LICENSE) for the terms governing use and distribution.

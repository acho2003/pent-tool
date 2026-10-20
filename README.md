# Xalgorix

Xalgorix is a self-hosted security assessment platform. It combines bounded
reconnaissance, web/API testing, host and network checks, source scanning, and
deterministic reporting in one dashboard and CLI.

Use it only against systems you own or are explicitly authorized to test.
Some scanners perform active requests.

## Choose an installation method

| Method | Best for | Requirements |
| --- | --- | --- |
| Docker Compose | Most users; includes the dashboard, ZAP, Greenbone, and scanner tools | Docker Desktop or Docker Engine with Compose |
| Native build | Developers and lightweight local experiments | Go, Node.js/npm, and the scanner binaries/services you need |

Docker Compose is recommended. It builds the checked-out source, so it works
on Apple Silicon and runs the code in your current checkout.

## Docker installation

### 1. Install prerequisites

Install Docker Desktop on macOS or Windows, or Docker Engine plus the Compose
plugin on Linux:

```sh
docker version
docker compose version
```

### 2. Clone the repository

```sh
git clone https://github.com/xalgord/xalgorix.git
cd xalgorix
```

### 3. Create the credential-encryption key

Xalgorix encrypts saved target credentials with a 32-byte key:

```sh
mkdir -p secrets
openssl rand -out secrets/xalgorix-credential.key 32
chmod 600 secrets/xalgorix-credential.key
```

Back up this file securely. If it is lost, saved credentials cannot be
recovered. Never commit it.

### 4. Configure the dashboard login

Create `.env` beside `docker-compose.yml`. It is git-ignored and must contain
only `KEY=value` entries; do not paste YAML into it.

For a simple local setup:

```dotenv
XALGORIX_USERNAME=admin
XALGORIX_PASSWORD=change-this-immediately
XALGORIX_STORE=postgres
XALGORIX_PG_PASSWORD=change-the-postgres-password
```

For production, prefer a bcrypt hash:

```sh
printf "XALGORIX_USERNAME=admin\nXALGORIX_PASSWORD_HASH='%s'\nXALGORIX_STORE=postgres\nXALGORIX_PG_PASSWORD='use-a-long-random-value'\n" \
  "$(htpasswd -nbBC 10 '' 'change-this-immediately' | cut -d: -f2)" > .env
```

Compose starts PostgreSQL 16. With `XALGORIX_STORE=postgres`, structured scan
records, credentials, and schedules use PostgreSQL; large scanner artifacts and
reports remain on the `xalgorix-data` volume.

### 5. Build and start

```sh
docker compose up -d --build
```

The first build can take several minutes because it compiles the application,
builds the web UI, and installs pinned scanner dependencies. Greenbone also
initializes vulnerability feeds on first use.

Open <http://127.0.0.1:9137> and sign in with the `.env` credentials.

Check the services:

```sh
docker compose ps
docker compose logs -f xalgorix
```

The app container should be `Up`; PostgreSQL should be `healthy`; ZAP should
eventually be `healthy`. Greenbone feed containers may take longer.

### Common Docker commands

```sh
# Stop containers but keep data.
docker compose down

# Start the existing stack.
docker compose up -d

# Rebuild after source changes and recreate only the app.
docker compose build xalgorix
docker compose up -d --no-deps --force-recreate xalgorix

# Follow application logs.
docker compose logs -f xalgorix

# Check PostgreSQL.
docker compose exec -T postgres pg_isready -U xalgorix -d xalgorix
```

Do not use `docker compose down -v` unless you intentionally want to delete
the named data volumes.

## Native installation

Native mode is useful for development. It does not install scanner tools at
runtime; missing binaries and unavailable services become explicit gaps.

Requirements include Go matching `go.mod`, Node.js/npm, and the scanner
binaries or services you intend to use. Build and run:

```sh
make build
./build/xalgorix --web
```

The dashboard is served on port 9137. Use `XALGORIX_*_PATH` variables for
non-standard scanner locations.

Development commands:

```sh
make webui-install
make webui
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go vet ./...
```

`CGO_ENABLED=0` matches the release build and avoids an optional CPU-detection
dependency crash on some ARM/macOS environments.

## First assessment

1. Open **New Assessment**.
2. Choose Web Application, API, or another assessment type.
3. Add an explicit target URL, such as `https://example.com/`.
4. Review the plan. Planning does not contact the target.
5. Select optional scanners if needed.
6. Start the assessment.
7. Review coverage, findings, native evidence, and the report.

Every planned scanner receives a terminal outcome: completed, failed,
cancelled, skipped, or not applicable. A successful process is not proof that
every check ran; the report includes coverage and limitations.

### CLI examples

```sh
xalgorix --target https://example.com
xalgorix --target example.com --vuls-ssh-host prod-web
xalgorix --source ./my-app --artifact-kind filesystem
xalgorix --source https://github.com/example/app.git --artifact-kind repository
```

For typed assessments, preview the JSON configuration before execution:

```sh
xalgorix --plan --assessment-config assessment.json
xalgorix --run-assessment --assessment-config assessment.json
```

Typed plans are fingerprinted. Starting with an old fingerprint is rejected if
scanner availability, credentials, API inputs, or the endpoint catalog changed.

## Kubernetes exposure scanning

`kube-exposure` is an optional URL-only black-box scanner. It is separate from
`kube-bench`:

- `kube-exposure` checks externally visible HTTP(S) surfaces and needs no
  kubeconfig or cluster credentials.
- `kube-bench` performs a CIS Kubernetes cluster/node audit and requires
  operator-provided cluster access.

The exposure scanner sends a small, versioned set of read-only GET requests for
same-origin, in-scope paths related to Kubernetes API discovery, Dashboard,
Argo CD, Prometheus, and Grafana. It follows only approved redirects, respects
the shared request budget, and does not guess credentials, namespaces, cloud
metadata, or mutation endpoints.

Fingerprints are informational. A confirmed exposure requires a response
predicate showing unauthenticated access to sensitive Kubernetes data or
functionality. A generic 200, 401, 403, ingress page, or product name alone is
not a confirmed vulnerability.

## DNS and target connectivity

The scanner runs inside the application container. A hostname that resolves on
the host may fail inside Docker if Docker inherits a broken local DNS resolver
or the target requires VPN/private DNS.

Test resolution from the container:

```sh
docker exec xalgorix-xalgorix-1 getent hosts target.example.com
```

If public DNS is appropriate, configure DNS under the `xalgorix` service in
`docker-compose.yml`:

```yaml
dns:
  - 1.1.1.1
  - 8.8.8.8
```

Do not put this YAML block in `.env`. If the target is private, use the required
VPN or internal DNS instead of public resolvers.

## Data, backups, and persistence

Docker named volumes hold application data:

```sh
docker volume ls | grep xalgorix
```

Back up both the credential key and persistent data. A basic PostgreSQL dump:

```sh
docker compose exec -T postgres pg_dump -U xalgorix xalgorix > xalgorix.sql
```

Scanner artifacts live under `/data/_assessments/` inside the container. They
include native output, checksums, findings, reports, and coverage records.
Keep artifacts protected; they may contain sensitive target information.

## Configuration reference

| Variable | Purpose |
| --- | --- |
| `XALGORIX_USERNAME` | Dashboard username |
| `XALGORIX_PASSWORD` / `XALGORIX_PASSWORD_HASH` | Dashboard authentication |
| `XALGORIX_STORE` | Set to `postgres` to use PostgreSQL records |
| `XALGORIX_POSTGRES_DSN` | Optional explicit PostgreSQL DSN |
| `XALGORIX_PG_PASSWORD` | PostgreSQL container password |
| `XALGORIX_CREDENTIAL_KEY_FILE` | 32-byte credential encryption key path |
| `XALGORIX_MAX_WORKERS` | Concurrent scanner limit; default `3` |
| `XALGORIX_ZAP_URL` / `XALGORIX_ZAP_API_KEY` | ZAP API connection |
| `XALGORIX_GVM_HOST` / `XALGORIX_GVM_PORT` | Greenbone GMP connection |
| `XALGORIX_GVM_SOCKET` | Greenbone UNIX socket; takes precedence |
| `XALGORIX_NUCLEI_PATH` | Nuclei executable path |
| `XALGORIX_TRIVY_PATH` | Trivy executable path |
| `XALGORIX_NMAP_PATH` | Nmap executable path |
| `XALGORIX_TESTSSL_PATH` | testssl.sh executable path |
| `XALGORIX_SCANNER_MAX_OUTPUT_BYTES` | Per-scanner output limit |

## API and reports

Important endpoints, normally used after dashboard authentication:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/scans/plan` | Validate and preview a typed assessment |
| `POST` | `/api/scan` | Start a legacy or typed scan |
| `GET` | `/api/scanners/registry` | List scanner capabilities and availability |
| `GET` | `/api/scanners/status` | Show scanner health/configuration |
| `GET` | `/api/scans/:id/coverage` | Show planned and completed coverage |
| `GET` | `/api/report/:id` | Download a PDF report |
| `GET` | `/api/scans/:id/:scanner/artifact` | Download a native artifact |

Reports group findings by scope and preserve evidence references to native
scanner artifacts. Scanner-reported findings should be reviewed and validated
in the affected environment; Xalgorix does not claim independent exploitation.

## Troubleshooting

### Compose says `.env` is invalid

`.env` accepts only `NAME=value` lines. Remove YAML, spaces before keys, and
unquoted values containing special characters:

```sh
docker compose config >/dev/null
```

### The dashboard is not reachable

```sh
docker compose ps
docker compose logs --tail=100 xalgorix
curl -i http://127.0.0.1:9137/
```

Check that port 9137 is free and Docker Desktop is running.

### A scanner failed

Open the scan coverage view and inspect stdout, stderr, and the native
artifact. Common causes are unavailable binaries/services, DNS failure, TLS
failure, scope rejection, authentication failure, or an exhausted budget. A
scanner failure does not automatically cancel other scanners.

### Greenbone is still starting

The first feed initialization can take a while:

```sh
docker compose ps
docker compose logs -f gvmd openvas ospd-openvas
```

### Credentials disappeared after rebuild

Set a fixed dashboard password in `.env` and keep
`secrets/xalgorix-credential.key`. A generated password changes on restart, and
losing the encryption key makes saved target credentials unrecoverable.

## Security notes

- Do not expose the dashboard publicly without authentication and network
  controls.
- Keep `.env`, the credential key, volumes, logs, and reports private.
- Use target-bound credentials only for authorized targets.
- Prefer bounded profiles for production systems.
- Review scope, exclusions, and plan coverage before starting an assessment.

## Further documentation

- [Web/API workflow](docs/web-api-workflow.md)
- [Security and target credentials](docs/security/target-credentials.md)
- [Source and container scans](docs/source-container-scans.md)
- [Runtime inventory and verification](runtime/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Proxy support](docs/proxy-support.md)
- [Contributing](CONTRIBUTING.md)

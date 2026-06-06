# Contributing to Xalgorix

Thanks for your interest in contributing. Xalgorix is a self-hosted,
autonomous AI pentesting engine: a single Go binary (`xalgorix`) that serves
an embedded React dashboard (`webui`) and runs scans locally. This document
covers the local development workflow.

## Prerequisites

Install the following on your workstation:

- **Go 1.25+** — building and testing the `xalgorix` binary.
- **Node.js 20+** and **npm** — building the embedded `webui` dashboard bundle.
- **GNU Make** — the entry point for every common task.

Optional but recommended:

- `golangci-lint` (v2.x), `gosec`, `govulncheck` — used by `make lint` and the
  security tooling / CI gates.

## Building and testing

The Makefile wraps every common task:

```bash
make build          # builds webui, then the binary into ./build/xalgorix
make run            # build + run the web UI locally
make test           # runs the Go test suite
make test-race      # tests with the race detector
make lint           # gofmt + go vet
make webui          # builds the embedded webui bundle into internal/web/static
make webui-dev      # runs the webui dev server (Vite) against a local backend
```

The dashboard sources live in `webui/` (React + Vite + TypeScript) and are
compiled into `internal/web/static/`, which is embedded into the Go binary at
build time. After changing anything under `webui/`, run `make webui` (or
`make build`) so the embedded assets stay in sync.

Run all Go tooling with the module's pinned toolchain (`go.mod` sets it). Keep
the tree `gofmt`-clean and `golangci-lint`-clean — both are blocking gates in
CI (`.github/workflows/ci.yml`).

## Project layout

| Path                 | Purpose                                                        |
| -------------------- | -------------------------------------------------------------- |
| `cmd/xalgorix/`      | CLI entry point and service lifecycle (`--web`, `--start`, …). |
| `internal/web/`      | HTTP server, dashboard API, and embedded static assets.        |
| `internal/agent/`    | The autonomous scanning agent loop.                            |
| `internal/llm/`      | LLM provider catalog, router, and client.                      |
| `internal/tools/`    | Terminal execution sandbox and the bundled skill set.          |
| `webui/`             | React dashboard sources (compiled into `internal/web/static`). |

## Spec-driven workflow

Larger features are developed through specs under `.kiro/specs/`. Before
opening a PR that touches a spec area, read the relevant `requirements.md`,
`design.md`, and `tasks.md` and make sure your change either implements an
open task or proposes a clearly scoped addition.

## Releases

Releases are cut with `./release.sh <version>` (e.g. `./release.sh 4.5.0`),
which bumps the version, builds, tags, pushes a `release/<version>` branch, and
opens a PR against `main`. `main` is branch-protected — never push to it
directly.

## Reporting issues

Open a GitHub issue with reproduction steps, expected vs. actual behavior, and
any relevant logs. For security-sensitive reports, see [`SECURITY.md`](SECURITY.md).

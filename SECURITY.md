# Security Policy

## Reporting a vulnerability

Please email security@xalgorix.com with details. We acknowledge reports
within two business days and aim to ship a fix or mitigation on a
severity-driven schedule. Do not file public GitHub issues for
suspected vulnerabilities.

## Daily scan policy

The [`security-daily`](.github/workflows/security-daily.yml) GitHub Actions
workflow runs every day at 07:00 UTC (and on `workflow_dispatch`). It executes
`govulncheck ./...` against the Go module. When it reports a vulnerability the
project actually calls into, the run fails and a GitHub Issue labelled
`security` and `automated` is opened with the report attached as a workflow
artifact. The job skips (and logs a notice) if `go.mod` is absent, so the
schedule keeps running regardless.

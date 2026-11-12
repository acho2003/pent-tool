# Microservice assessments: services, shared token login, registry login

Date: 2026-11-12. Status: approved direction (owner chose: services table +
CSV/YAML import, log-in-once token reuse, registry login; remaining details
delegated to the implementer).

## Problem

A microservice application (example: 15 BCRS services, each with its own
internal origin, container image and lockfile) currently has to be entered as
loose targets. Credentials are bound to one target in the UI, so authenticated
ZAP runs one service at a time. Image scans cannot log in to a private
registry, require digest pins, and the report groups by host rather than by
service. Vendor CI reports (per service: ZAP, Trivy image, dependency scan,
pnpm audit) show the desired per-service shape.

## Decisions

### 1. Services are a grouping layer over existing targets

`assessment.Config.Services []Service{ID, Name, TargetIDs}`.

- IDs and names unique (names case-insensitive), 1–128 printable characters.
- Every target ID must exist; a target belongs to at most one service; a
  service has at least one target. Ungrouped targets stay valid.
- Planning, scope, jobs, coverage and finding identity are unchanged: each
  service's URL/image/repo is an ordinary target. Services are part of the plan
  config and therefore the fingerprint.
- Records without `services` behave exactly as before.

### 2. `TOKEN_LOGIN` credential (log in once, bearer token everywhere)

Vault values: `login_url`, `username`, `password`, `username_field`,
`password_field` (defaults `username`/`password`), `body_format` (`json`
default | `form`), `extra_fields` (JSON object of non-secret strings, e.g.
`client_id`, `grant_type`), `token_path` (optional dot path; auto-detects
`access_token`, `accessToken`, `token`, `jwt`, `id_token`, `data.token`,
`data.accessToken`, `data.access_token`), `header_name` (default
`Authorization`), `header_prefix` (default `Bearer `).

- One binding per service URL target, all with the same credential ID; each
  binding may carry its own `verify_url` (protected path) and marker.
- The login URL's origin must equal the origin of a URL target in the same
  assessment and be inside that target's application scope. The password goes
  nowhere else. Redirects from the login request are not followed off-origin.
- The token is injected only for targets explicitly listed in a binding of
  that credential (existing per-target gateway header injection). Discovered
  origins never receive it.
- Server logs in once per (credential ID) during auth resolution and reuses the
  token for every bound target. Failure → each bound target marked `failed`
  with a fixed, secret-free reason; authenticated jobs skipped as today.
- Per-target verification: with `verify_url`, authenticated request must be
  2xx (and contain marker if given) and an anonymous request must not succeed
  identically → `verified`. Without `verify_url`, the target is scanned with
  the token and marked `unverified` with reason "token applied; access not
  verified (no protected path supplied)". Nothing claims verification.
- Renewal: proactive when the JWT `exp` claim (decoded, signature not checked)
  is within 60 s; reactive on the existing expiry hook. One lock and one
  renewal budget per credential so 15 services trigger one login.
- Token is runtime-only: never persisted, logged or placed in artifacts; added
  to the sanitizer secret list. After restart a fresh login is required.

### 3. `REGISTRY_CREDENTIALS` credential (Trivy private registry)

Vault values: `registry` (host[:port]), `username`, `password`.

- Bound to `DOCKER_IMAGE` targets. Resolved at runtime like cloud credentials
  into `Config.AssessmentRegistryCreds[targetID]`; passed to Trivy only via
  `TRIVY_USERNAME` / `TRIVY_PASSWORD` env and added to `req.Secrets`.
- Used only when the image reference's registry host equals `registry`;
  otherwise the job runs without it and records why.
- Image references may be tags (`host/repo:tag`) as well as digests. For tags
  the run records a `mutable_image_tag` limitation and the digest Trivy
  actually scanned (from `Metadata.RepoDigests`/`ImageID` in its JSON) so the
  report states exactly what was tested. White Box mode is still required.

### 4. Import / export

`POST /api/services/parse` accepts CSV or YAML (≤1 MiB) and returns rows plus
per-row errors. CSV header: `name,url,image,repo` (`url` may hold several URLs
separated by `;`; `protected_path` optional column). YAML: list of
`{name, urls|url, image, repo, protected_path}`. No targets are scanned from
the import alone; rows populate the table for review.

### 5. UI (New Scan)

- "Services" table in the target card: name, URL(s), image, repo/source,
  protected path. Add/remove rows, import CSV/YAML, export CSV. Service rows
  generate targets `svc-<n>-url-<k>`, `svc-<n>-image`, `svc-<n>-repo` and the
  `services` config. The plain textbox still works for ungrouped targets.
- Target access: new credential type "Shared login (token)" with login API URL,
  username/password, field names, format, token path, and a checkbox list of
  service URL targets (default: all). Saves one vault record bound to all
  ticked targets; bindings carry each service's protected path.
- Registry login: shown when any image is present; registry host, username,
  password; bound to all image targets on that host.

### 6. Report and scan detail

- `reportScope.Service`; findings mapped target → service via job scope
  (`app:<id>` / `host:<id>`).
- New "Services overview" table: service, targets, Critical/High/Medium/Low/
  Info, authentication state, scanners completed/failed/skipped.
- Findings summary and detail sections are grouped/labelled by service when
  services exist; ungrouped targets appear under "Other targets".
- Scan detail page shows the same services overview from the same saved data.
- Report version bump so cached reports regenerate.

## Testing

- Assessment validation unit tests for services.
- Token login: httptest auth service issuing JWTs + two bearer-protected
  services; asserts one login for many targets, per-target verified/unverified
  states, origin restriction of the password, token not sent to unbound
  targets, renewal shares one login, token absent from saved plan/records.
- Registry: env injection only on host match, secrets redacted, tag allowed
  with limitation, digest extraction from Trivy JSON fixture.
- Parse endpoint: CSV/YAML happy path, multi-URL, errors, size limit.
- Report: services overview counts and grouping; legacy record unchanged.
- Full Go suite (CGO off), UI typecheck + build.

## Out of scope

Importing vendor CI artifacts; per-service scan scheduling; changing the
White Box requirement for images; private-registry pulls for anything but
Trivy.

# Pinned Next.js framework acceptance

This is an intentionally vulnerable, loopback-only test application and a patched counterpart, built with pinned Next.js 16.4.3 and React/React DOM 19.3.1. The npm lockfile pins their dependency graph. They use synthetic records and role cookies; no production target or credential is needed.

Run from the repository root with Node.js compatible with the pinned Next.js package (tested with Node 24.18.0), npm, Python 3, and the module-pinned Go toolchain:

```sh
python3 test/nextjs-lab/run.py
```

The driver installs locked dependencies with package scripts disabled, builds both variants, allocates loopback ports, starts two owned production `next start` processes and an owned callback collector, runs `TestNextjsFrameworkAcceptance`, and stops only those subprocesses. It does not start, stop, rebuild, or reconfigure the dashboard or any existing containers. The application processes bind explicitly to `127.0.0.1`. Build telemetry is disabled. Their build folders and dependencies stay ignored by Git.

Reuse existing builds or choose a scorecard path:

```sh
python3 test/nextjs-lab/run.py --skip-build --results /tmp/nextjs-scorecard.json
```

Rebuild after changing fixture source or configuration. The real-framework test is opt-in and skips in ordinary `go test ./...`. The driver supplies loopback-only URLs and verifies the fixture identity/variant/collector before testing. URL-shaped environment variables cannot point this acceptance test at an external application.

## Matrix and measured baseline

The HTTP matrix gates eleven checks on each counterpart:

- Production browser source-map exposure.
- Bounded decoding of embedded source entries from actual production maps.
- Controlled HTML access.
- Pages Router `/_next/data/<observed-build-id>/...` access.
- Real App Router RSC access for anonymous and reader identities, each with an owner baseline.
- Server Action identity authorization, using an action reference observed in the actual rendered form and the real Next.js action dispatcher.
- Built-in Server Action origin rejection.
- Controlled application-cache identity isolation and verified reset.
- Paired local/external redirects, never followed.
- Correlated outbound URL-fetch policy against the owned collector.

The vulnerable variant deliberately exposes the selected source maps, private page props, missing action authorization, controlled cache leakage, redirect policy failure, and an outbound fetch to the owned collector. The patched variant enforces the intended policies. Both retain Next.js's built-in action-origin guard. The proxy is confined even in vulnerable mode to its owned callback origin and `/hit` path; this lab is not an unrestricted network proxy.

The RSC resource is a rendered App Router page, not a route handler returning a synthetic flight-like string. The driver first makes an owner RSC request without following redirects, then captures the framework-supplied canonical resource URL. It accepts only the same origin/path with exactly one `_rsc` query; native comparisons use that exact URL with `RSC: 1` and `Accept: text/x-component`. No router-state tree or cache-busting hash is invented. The patched fixture's `proxy.js` authorizes before rendering and returns an explicit 403 for nonowners. A streamed error with HTTP 200 and no private marker remains inconclusive to the native scanner; absence of the marker alone is not proof of denial. This remains HTTP-level RSC acceptance, not a browser navigation or flight-decoder test.

The cache is a deliberately controlled application cache inside a real Next.js route handler, not a measurement of Vercel or an external CDN. The proxy is a controlled route handler, not a claim that the Next.js image optimizer is vulnerable. Missing callback events remain an inconclusive native outcome, even for the patched fixture whose source rejects the fetch. The negative control gate checks for no false finding and retains that `PARTIAL` outcome.

The checked-in `baseline.v1.json` records the measured 22/22 passing HTTP subset of the browser-enabled matrix on 2026-11-03. `recorded_requests` counts native request receipts, excluding authentication checkpoints and driver readiness requests. The action-origin row reuses the action campaign, and the embedded-map analysis row reuses the map exposure requests; each identifies `shared_with` and records zero additional requests to avoid double-counting. Source-map exposure is counted as one class even when multiple map URLs are confirmed. These gates are fixture-level detection checks, not general precision/recall guarantees across arbitrary deployments.

## Authenticated Chromium discovery

Add the production browser recorder with an explicit Chromium/Chrome executable:

```sh
python3 test/nextjs-lab/run.py --browser /path/to/chromium
```

This adds twenty-four gates: hydrated discovery and automatic client-side navigation, each with owner, reader, and anonymous identities against both counterparts, plus eight login/session gates and four observed-multipart campaign gates, giving 46 total. The real Next.js Client Component waits 650 ms after hydration, imports a separate lazy module, and issues a read request. The same callback attempts a synthetic POST, which must be blocked before it reaches Next.js. The gates require an observed successful lazy read, JavaScript chunk observations, identity-specific encrypted replay with the expected cookie, no credential value in public artifacts, a nondispatchable POST form, and zero server-side writes. Navigation gates use the real `next/navigation` router to transition to a rendered App Router page. They additionally require the observed successful RSC request, its original RSC/router-state headers and identity cookie in encrypted replay, and destination forms attributed to the final rendered URL. The scanner does not construct a router-state tree or follow arbitrary buttons. Each discovery run uses a fresh browser profile and replay store.

Login gates drive the production `CaptureBrowserLogin` adapter through a real React-controlled login form, a JSON fetch sign-in response, an HttpOnly cookie scoped to `/workspace`, and Next.js client-side routing to a protected server-rendered page. They verify owner and reader cookies against the fixture session endpoint, reject a wrong password in a fresh profile, require an anonymous browser to fail the protected marker check, and require login workspaces to be removed. The synthetic fixture implements this flow directly; it is not a full Auth.js, OAuth, MFA, or SSO integration. Login capture selects cookies for the protected application path and rereads cookies/storage after verification, including session refreshes. Verification must use the login origin and approved scope. The browser version is recorded in the scorecard; it is not pinned by the npm framework lockfile.

Multipart gates observe an actual browser-submitted Next.js form with a five-byte synthetic binary file. An owned loopback HTTP proxy forwards only GETs to the owned fixture and captures the original multipart POST without forwarding it to Next.js. Browser-native transport preserves file bytes; no DevTools text-body reconstruction is used. The proxy refuses other origins and methods. The native action adapter then uses the captured Next-Action ID, Content-Type, boundary, and immutable body in the same finite identity/origin campaign as text actions. Each case must prove controlled state and verified reset. No action body is generated, mutated, or stored in the scorecard. The captured browser submission and prerequisite GETs are excluded from native request counts; the replay campaign receipts are counted, with origin checks sharing the campaign's counts.

The browser recorder now waits for a full second of network quiet after page load, within its existing 20-second page deadline and shared limits. Delayed work beyond that settling window is not guaranteed to be discovered. Idle deadline failures are reported as partial navigation coverage. Expected blocked writes also retain a `PARTIAL` outcome; a passing fixture gate does not turn excluded operations into complete coverage. This acceptance covers hydrated reads and identity isolation, not arbitrary interactive workflows or external identity-provider flows. DOM inventory follows the final browser URL, checks its scope/exclusions before retaining forms and links, and marks inventory/evaluation failures as partial coverage.

`baseline.browser.v1.json` records the measured 46/46 passing matrix on 2026-11-03, including the local browser version. Browser request counts include recorded successful HTTP responses, exclude DOM-only inventory and blocked requests, and exclude prerequisite/session-check requests as with the native HTTP matrix. Login capture does not expose HTTP receipt counts, so login rows use `requests_untracked: true` with zero as a placeholder; their requests are not zero-cost and any sum is only a lower bound. No credentials, cookie values, protected response bodies, or raw login output are included in the scorecard. The CI workflow enables the browser gates with the runner's installed Google Chrome; a missing browser fails the gate rather than skipping it.

The driver writes a fresh `lab-results.json` (ignored by Git), including failure status if the test matrix is incomplete or a gate fails. The GitHub Actions workflow in `.github/workflows/nextjs-acceptance.yml` repeats this matrix for relevant changes and publishes that scorecard.

## Bounded embedded-map checks

The deep asset adapter examines up to eight recognized public maps, reading at most 1 MiB each with the existing overall byte/request budget. It decodes version-3 `sourcesContent` in memory, with a 1,000-source cap. Private keys must pass local cryptographic parsing; source API strings remain redacted unverified candidates and are never automatically requested. Source filenames/URLs and indexed sections are never fetched. Truncated/unsupported/malformed/over-limit analysis stays partial while map exposure findings survive. The production gate requires decoded embedded entries from the vulnerable build and no such exposure from the patched build. Confirmed findings from a later budget-interrupted asset run survive only with a verified artifact checksum, and are labeled partial. Go fixtures additionally exercise an ephemeral private key beyond 4 KiB with JSON Unicode escapes, fake keys/public configuration, null/missing sources, redaction, no source/API fetches, map count/size bounds, indexed maps, and invalid JSON.

## Real offline source-engine acceptance

The bundled rule pack is also tested against the runtime-pinned Semgrep 1.178.0 engine. The positive fixtures cover six rule IDs and eight intended matches, including common URL/search-parameter aliases. Negative fixtures use public configuration, fixed destinations, and constant allowlisted redirect mappings.

With a native Semgrep binary:

```sh
CGO_ENABLED=0 XALGORIX_TEST_SEMGREP=semgrep \
  go test ./internal/scanner -run '^TestNextjsSAST' -count=1
```

With the existing purpose-built `xalgorix:local` image:

```sh
CGO_ENABLED=0 XALGORIX_TEST_SEMGREP="$PWD/test/nextjs-lab/semgrep-runtime.sh" \
  go test ./internal/scanner -run '^TestNextjsSASTRealEngine$' -count=1
```

The test-only Docker adapter uses the already-cached image (`--pull never`), no network, a read-only container root, a nonroot UID, resource limits, and a bind mount containing only the native runner's temporary bounded snapshot/rules/output. It does not mount the source repository or Docker socket inside the scanner container. `XALGORIX_SEMGREP_IMAGE` can select another already-cached compatible image; the documented baseline was measured with the runtime's Semgrep 1.178.0.

Production source checks are a separate optional `nextjs-sast` scanner, also selected for applicable source targets by the `nextjs-deep` profile. The engine binary is still required. No Next.js config, npm hook, package script, or application code is executed during source scanning.

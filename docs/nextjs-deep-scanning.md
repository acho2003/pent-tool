# Next.js deep assessments

Choose **Next.js deep** as the web profile in a typed Web Application or API assessment. Preview the generated plan before starting it. The profile is also available for typed schedules. Existing saved plans need a fresh preview because registry version 21, asset catalog v6, and action catalog v2 change execution identity.

The profile selects the native `nextjs-assets` adapter and native resource checks alongside the ordinary applicable scanners. Explicit custom scanner selections take precedence. Optional scanners still need to be selected, and unavailable external tools remain visible gaps. Selecting the profile does not change scope or enable the opt-in unified workflow.

## What this release adds

- HTML parsing for script/module/preload references, including single-quoted attributes, base paths, and query strings.
- Bounded traversal of explicit page links and literal Next.js chunk references. App Router bootstrap references can supply asset URLs; this is not a complete flight protocol parser.
- API URL strings from pages, bundles, and decoded embedded map sources as unverified inventory candidates. These strings do not cause speculative API requests. Observed browser requests continue through the existing inventory workflow.
- Adjacent `.map` probes when a script has no explicit map reference. Source-map findings require top-level version 3 and typed sources/mappings/sections evidence, rather than a successful status alone.
- Local validation of unencrypted PEM private keys in anonymous pages, scripts, and bounded decoded source-map contents. Values, excerpts, and key-derived fingerprints are not retained or used against other services. Public configuration names alone do not produce secret findings.
- Controlled resource access comparisons for HTML, Pages Router JSON, and RSC, with distinct representation/identity coverage IDs and content-type validation. These comparisons require the expanded workflow described below.
- Per-request discovery receipts and explicit request, byte, script, page, and endpoint limit reporting. Discovery receipts are not counted as active security testing.

## Budgets

The overall profile permits 10 requests/second, 3,000 unique endpoint variants, and 90 minutes. Native Next.js discovery is additionally bounded to:

| Setting | Default | Maximum |
| --- | ---: | ---: |
| `max_pages` | 25 | 250 |
| `max_scripts` | 120 | 500 |
| `max_route_checks` | 200 | 500 |
| `max_requests` | 600 | 5,000 |
| `max_response_bytes` | 67,108,864 | 268,435,456 |

The new-assessment form exposes these settings under **Next.js discovery limits**. Zero or an omitted field uses the default. API/CLI assessment configuration accepts the same `nextjs` object; all settings participate in the accepted plan fingerprint:

```json
{
  "assessment_mode": "BLACK_BOX",
  "assessment_types": ["WEB_APPLICATION"],
  "assessment_targets": [
    {"id": "app", "type": "URL", "value": "https://app.example.test/portal/"}
  ],
  "profile": "nextjs-deep",
  "nextjs": {"max_pages": 40, "max_scripts": 180, "max_requests": 900}
}
```

Pages are parsed up to 512 KiB and scripts up to 2 MiB. Ordinary map probes inspect only their first 4 KiB. The deep profile instead reads up to 1 MiB per map for at most eight recognized maps, within the same shared request and byte limits. Supported version-3 regular maps and embedded index sections may supply up to 1,000 source entries across the whole map for in-memory private-key checks and literal API candidate extraction. The map schema follows the [ECMA-426 source map format](https://tc39.es/ecma426/2024/); mappings are not decoded into original line positions. Embedded indexed maps are traversed to a maximum depth of four, with at most 64 sections across the whole map. Source entries keep generated section/index locations rather than filenames. Neither `sourceRoot`, source filenames/URLs, nor external section URLs are resolved or fetched. Nullable/missing source contents do not cause speculative requests. Truncated, malformed, external-section, depth-limited, count-limited, or candidate-limited analysis retains exposure evidence and reports `PARTIAL`; valid embedded siblings remain eligible for key checks and API candidate extraction even when another section is unsupported; maps beyond the eight-map cap receive structure-only probes. Source excerpts, source filenames, key values, and raw maps are not retained. Confirmed asset findings survive a later failed/cancelled run as partial evidence only when their sealed artifact checksum verifies. Response parsing limits and failed requests are reported; reaching a limit is not evidence of a clean application. Literal route candidate inventory is bounded to 500 entries. Native discovery remains anonymous, does not submit forms, follows no redirects, and never forwards configured target or global credential headers to assets. Existing verified browser discovery supplies authenticated observations when that workflow is enabled.

## Controlled access comparisons

Enable `XALGORIX_UNIFIED_WORKFLOW=1` in the scanner environment to use the existing expanded identity/comparison workflow. This remains opt-in. Save at least one target-bound named identity and select **Role access expectations** in a Gray Box or White Box web/API assessment.

1. Choose API operation, HTML page, Pages Router JSON, or App Router RSC.
2. Supply an API operation ID, or a unique comparison ID for a web representation.
3. Supply the exact controlled resource URL and a nonsecret, unique response marker from test data.
4. Select the allowed identity and another denied identity, or **Anonymous**.
5. Save the fixture and expectations, then preview the plan.

API comparisons still require a matching materialized GET operation. Explicit web-representation fixtures do not require an invented OpenAPI definition. Their URLs must belong to the original target origin and approved path scope. RSC checks send `RSC: 1` and `Accept: text/x-component`; they do not invent router-state trees or action IDs. Supply exact JSON data URLs rather than expecting a build ID or dynamic route value to be guessed.

A content-addressed resource fixture has this form:

```json
{
  "url": "https://app.example.test/portal/account",
  "response_marker": "CONTROLLED_TEST_RECORD_42",
  "representation": "rsc"
}
```

The representation is omitted for existing API fixtures. The expectation identity `anonymous` is reserved for requests without credentials; it cannot be used as a named credential identity. Every comparison requires dispatcher selection, its own authentication checkpoint, and the shared budget. Generic 200 responses, login pages, redirects, incorrect media types, missing allowed baselines, and expired identities cannot confirm unauthorized access. Reports persist response digests and marker confirmation, not response bodies or marker values.

## Controlled Server Action campaigns

The **Controlled Server Action tests** card in Gray Box and White Box web/API assessments now supports explicitly approved campaigns. It requires `XALGORIX_UNIFIED_WORKFLOW=1`, an explicit URL target, a declared test environment, a named owner bound to that target, and disposable controlled data. The deep profile alone never selects this write adapter.

Supply an observed `Next-Action` header ID (40–64 hexadecimal characters), the exact action URL, and its exact request body. Header-based actions using `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data` are supported. For multipart, select **Exact multipart body file**, upload the raw observed body including boundaries and binary parts, and supply the complete original Content-Type with its matching boundary. The UI uploads those bytes directly rather than constructing a new FormData payload. Multipart framing is validated at preview and execution, with at most 64 named form parts and 256-byte field names; filenames are not opened or interpreted. Missing/invalid boundaries, incomplete parts, empty bodies, and excessive part counts fail before campaign traffic. The body is never re-encoded or mutated. Request and optional cleanup bodies are uploaded as immutable private fixture references, each bounded to 64 KiB. The form saves a manifest reference rather than placing arguments or state markers into the assessment record.

Every campaign enumerates two to eight unique identity/origin cases. The first case must be an allowed same-origin owner baseline. Every later case must expect denial for another named identity, anonymous access, or a cross-origin owner request. The form creates the baseline and denied-identity case, with an optional third origin case. API configurations can enumerate additional cases; at most 20 campaigns may be approved in one assessment.

For each case the adapter:

1. Uses the owner to confirm the verification URL contains only the supplied ready marker.
2. Verifies the acting identity, durably journals its one-shot intent, and sends exactly one approved POST with the supplied action ID and body.
3. Uses the owner to read the verification URL independently. Only the changed marker proves the controlled operation occurred. An HTTP success or action response string cannot establish execution.
4. Attempts the exact declared DELETE, PUT, or PATCH cleanup with the owner's credentials, then verifies that the ready marker is restored.
5. Stops subsequent cases if the baseline, identity, state, journal, or cleanup cannot be verified. Confirmed findings from earlier checks remain available as partial results.

The state endpoint must synchronously distinguish two non-overlapping nonsecret markers of 8–2,000 bytes. A response containing both markers, neither marker, a redirect, a non-success status, an oversized body, or an expired owner session is inconclusive. Verification GETs, POSTs, and cleanup stay on the original target origin and approved path scope; method exclusions apply independently to each. No redirect is followed, and global/primary credentials are never substituted for a case identity.

An origin case changes only the POST's `Origin` header to `https://xalgorix.invalid`; it never connects to that host. A finding proves a violation of the explicitly supplied origin expectation, not a complete browser CSRF exploit. Next.js documents origin checks and configurable allowed origins in its [Server Actions configuration](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions).

If the POST's outcome is unknown, the adapter leaves an unresolved intent and sends no automatic retry or cleanup. It reports that manual cleanup may be required. The entire campaign refuses replay when any of its cases is already journaled, including after a restart or a changed plan fingerprint. Run further tests in a new explicitly reviewed assessment after resolving the controlled state. Renaming an approval is not a recovery mechanism.

API/CLI assessment configuration accepts campaign metadata:

```json
{
  "nextjs_action_approvals": [{
    "id": "controlled-profile-update",
    "target_id": "app",
    "fixture_ref": "<SHA-256 reference to uploaded action manifest>",
    "owner_identity": "owner",
    "cases": [
      {"id": "baseline", "identity": "owner", "expect": "allow"},
      {"id": "anonymous", "identity": "anonymous", "expect": "deny"},
      {"id": "foreign-origin", "identity": "owner", "expect": "deny", "cross_origin": true}
    ]
  }]
}
```

The uploaded manifest contains exact URLs and body references:

```json
{
  "url": "https://app.example.test/account",
  "action_id": "<exact observed hexadecimal Next-Action header>",
  "body_ref": "<SHA-256 reference to uploaded request body>",
  "content_type": "text/plain;charset=UTF-8",
  "verification_url": "https://app.example.test/test-fixtures/state",
  "ready_marker": "CONTROLLED_READY_42",
  "changed_marker": "CONTROLLED_CHANGED_42",
  "cleanup_url": "https://app.example.test/test-fixtures/reset",
  "cleanup_method": "DELETE"
}
```

For a body-bearing cleanup, also supply `cleanup_body_ref` and `cleanup_content_type`; PUT and PATCH require these. Preview validates the manifest, nested checksums, supported formats, scope, and exclusions without contacting the target. Runtime repeats those validations before any campaign traffic.

Findings and reports retain case IDs, identity contexts, response digests, controlled-state confirmation, cleanup status, and request evidence. They do not retain action arguments, credential values, state markers, or response bodies. Each action case has its own request identity and active-test receipt; state and cleanup requests are not counted as extra active action tests.

## Controlled cache, redirect, and URL-fetch boundaries

The **Controlled cache and URL boundaries** card adds three explicit fixture-based probes. They require a Gray/White Box typed URL assessment, `XALGORIX_UNIFIED_WORKFLOW=1`, a declared test environment, and a reviewed `nextjs_boundary_approvals` entry. The deep profile alone selects none of these probes. At most 20 boundary probes may be approved per assessment.

### Cache identity isolation

Use an isolated synthetic resource, an allowed named owner, and a different denied identity or anonymous access. Supply the owner and consumer response formats independently (HTML, page JSON, or RSC), non-overlapping private/denied markers, an uncached control URL using the same resource path with a different supplied query, and an exact DELETE/PUT/PATCH reset. PUT/PATCH require a private body fixture; bodies are bounded to 64 KiB.

The probe first confirms denial on both the cold resource and uncached control. It journals a one-shot intent before the owner fills the cache, confirms the owner's private marker, then repeats the consumer request and uncached control. Reset is attempted after an answered fill, including an inconclusive comparison. A successful reset status is insufficient: the consumer must again be denied on the original resource. Failed or ineffective reset stops remaining probes; confirmed disclosure findings are retained with partial results.

A private marker crossing the identity boundary is a confirmed disclosure even if its cache cause remains unverified. Cache attribution is marked **confirmed** only when the post-fill uncached control still denies access and the leaking response also has an explicit cache-hit indicator (`X-Nextjs-Cache`, `X-Vercel-Cache`, `CF-Cache-Status`, or `X-Cache` equal to `HIT`, or a positive `Age`). Header differences alone do not produce findings. Cross-representation private leakage is tested even if the leaking response has the wrong media type for the consumer request.

The scanner does not invent a bypass query or assume the supplied query bypasses your CDN. If both the original and control disclose private data, disclosure can be confirmed while cache attribution remains unverified. A cold response that already permits the denied identity stops the fill; use the ordinary controlled access comparisons to investigate that boundary.

Cache intents persist across attempts and plan revisions. Any previously journaled cache probe refuses automatic replay. Unknown fill outcomes leave unresolved intents, send no automatic reset, and report that manual cleanup may be required.

### Paired redirect policy

Supply an observed GET URL with exactly one selected query parameter, its exact local control value, and an explicitly disallowed controlled external destination. The original request must first redirect to the expected local destination. Only then is the selected parameter replaced with the external URL. A finding requires a redirect to that exact external origin/path/query. Neither response is followed, including redirects back into the approved application.

The external destination must already be explicitly in the reviewed application scope. The form adds the original application prefix and the exact controlled destination path to `approved_origins` when you approve the probe. It does not approve an entire external host by default.

### Image/proxy URL-fetch policy

Supply an observed GET URL with exactly one URL-valued query parameter, a controlled callback URL expected to be denied by the application, and a distinct anonymous event-feed URL on the same callback origin. Both external paths must be explicitly approved in scope. This authorizes the scanner to observe the controlled service; it does not change the application's intended destination policy. The form includes these paths in the reviewed scope after explicit approval.

The scanner generates a fresh 128-bit random correlation value and reads the event feed first. The feed must report zero matching events before any target probe. The scanner then substitutes the callback URL with a `scan_token` query into the observed parameter and makes one target request. It never requests the callback URL itself or follows a target redirect. It reads the anonymous feed up to three more times, with 200 ms between later reads, under the shared request/time budget.

The controlled service must:

- Record requests to the callback path by the exact `scan_token` query value, without redirecting them elsewhere. Serve a small benign response.
- Provide a read-only event-feed GET accepting the same query. Reading the feed must not create callback events.
- Return a bounded JSON object such as `{"token":"<exact scan_token>","count":0,"method":"GET"}` before a hit and a positive count with `GET` or `HEAD` afterward.
- Be operated by the tester and accept anonymous correlation reads for this isolated test data. Collector credentials, arbitrary event APIs, and third-party callback services are not inferred or auto-configured.

A finding requires a matching fresh-token GET/HEAD event after the target request. A generic target HTTP 200, reflected URL, stale event, wrong token, or missing callback cannot prove an outbound fetch. Missing events remain **inconclusive**, including when the target returned an error; asynchronous fetches can occur after the bounded observation window. Findings describe a violation of the supplied denied-destination expectation at medium severity. They do not claim internal-network access, credential theft, or a complete SSRF exploitation chain.

No cloud metadata, private-network address range, redirect chain, or callback destination is generated automatically. Only the supplied controlled service is used. App/collector scope, method exclusions, DNS-aware execution guards, credential origin binding, and no-redirect clients apply. Target, primary, and global credentials are never sent to the event feed. The execution guard also vets the callback/sink destination before any probe traffic.

Next.js image deployments should review [remotePatterns, redirect limits, and local-IP restrictions](https://nextjs.org/docs/app/api-reference/components/image). These probes exercise observed inputs and the supplied policy; they do not infer framework defaults from headers.

### Boundary fixture/API configuration

Approval metadata is separate from private manifest contents:

```json
{
  "nextjs_boundary_approvals": [{
    "id": "controlled-private-cache",
    "target_id": "app",
    "kind": "cache",
    "owner_identity": "owner",
    "identity": "anonymous",
    "fixture_ref": "<SHA-256 reference to uploaded boundary manifest>"
  }]
}
```

A cache manifest:

```json
{
  "kind": "cache",
  "url": "https://app.example.test/account",
  "representation": "pages-json",
  "consumer_representation": "rsc",
  "private_marker": "PRIVATE_CONTROLLED_42",
  "denied_marker": "DENIED_CONTROLLED_42",
  "bypass_url": "https://app.example.test/account?controlled_bypass=1",
  "isolated": true,
  "cleanup_url": "https://app.example.test/test-fixtures/reset-cache",
  "cleanup_method": "DELETE"
}
```

A proxy manifest (use approval kind `proxy`, omit `owner_identity`, and select the acting `identity`):

```json
{
  "kind": "proxy",
  "url": "https://app.example.test/_next/image?url=%2Fcontrolled.png&w=64&q=75",
  "parameter": "url",
  "callback_url": "https://collector.example.test/hit",
  "events_url": "https://collector.example.test/events"
}
```

For redirects, use kind `redirect`, `url` such as `https://app.example.test/login?next=%2Faccount`, `parameter: "next"`, `control_value: "/account"`, and `destination_url` for the controlled external sink. Callback/sink URLs have no embedded credentials, fragments, or existing query parameters. Cache-only and URL-probe-only fields cannot be mixed.

For API configurations, include the original target prefix and explicitly approved callback paths in `approved_origins`, with `target_id`, `scheme`, `host`, `port` if non-default, and `path_prefix`. Explicit origins replace the target's derived default scope, so omitting the original target prefix is invalid. Manifests and reset bodies are validated by checksum, kind, bounds, scope, exclusions, and supported format at preview and again at runtime. Probe metadata, scope, fixtures, and adapter catalog versions participate in the accepted plan fingerprint.

Reports show controlled probe results, cache attribution, reset status, callback correlation digests, and per-request evidence. Synthetic marker values, credentials, reset bodies, and response bodies are not retained in findings or reports. Generated callback URLs contain nonsecret random correlation values in the selected URL parameter. Each materialized URL input is recorded in its own selected request identity; baseline, bypass, reset, and event-feed controls do not inflate active-test counts. Every response is read up to 64 KiB. A cache probe uses at most seven application requests, redirect probes two, and proxy probes one target request plus up to four event-feed reads, excluding existing authentication checkpoints.

## Offline Next.js source checks

The optional **Next.js source checks** adapter (`nextjs-sast`) uses the configured Semgrep binary with a bundled, fingerprinted rule pack instead of `--config auto` or registry rules. Select it explicitly for a White Box source/repository target, or use `nextjs-deep`, which selects it for applicable source targets. Availability is tied to Semgrep, and repository checkout retains the existing target-bound credential flow. The generic Semgrep adapter remains independent and can have its own availability/network outcome.

Six rule IDs cover:

| Rule | Observation | Severity |
| --- | --- | --- |
| `nextjs-config-private-env-inline` | Potential private key/value configured through Next.js `env` | Medium review finding |
| `nextjs-config-local-image-fetch` | Explicitly enabled local-IP image optimization | Low configuration review |
| `nextjs-config-wildcard-action-origins` | Global wildcard Server Action origin configuration | Medium review finding |
| `nextjs-route-query-redirect` | Local query-input flow into a redirect | Medium review finding |
| `nextjs-route-query-fetch` | Local query-input flow into server-side fetch | Medium review finding |
| `nextjs-route-private-env-response` | Potential private environment value flowing into JSON response serialization | Medium review finding |

These are static configuration/local-dataflow observations, not confirmed exploits or proof that a deployed value is secret. They never infer missing authorization merely from the absence of a familiar authentication helper. Reading a non-public environment variable inside a Client Component is not automatically reported as a leak: framework handling matters. Public configuration, fixed fetch destinations, and constant redirect mappings have negative controls.

Next.js documents that values in [next.config env are included in the JavaScript bundle](https://nextjs.org/docs/pages/api-reference/config/next-config-js/env); the pack flags potentially private names for review rather than copying their values into evidence. Redirect/fetch sources support direct NextRequest search-parameter access, Pages API query access, direct `new URL(request.url).searchParams.get`, destructured `searchParams`, and local parsed-URL aliases. Whole-program/interprocedural validation, arbitrary aliases, dynamic config evaluation, Server Action authorization proof, and all client/server serialization paths are outside this pack's static scope.

Source scanning does not run Next.js configuration, imports, npm hooks, package scripts, or application code. The native adapter opens the supplied directory with a rooted filesystem handle and copies regular eligible configuration/API-handler files into a private temporary snapshot. It never follows project symlinks. Node modules, VCS metadata, generated `.next*` output, build/dist/out, coverage, and vendor directories are excluded. Select the intended application root; unrelated checked-in fixture/example applications are not assumed to be production or automatically suppressed.

Bounds are 20,000 walked entries, 5,000 selected files, 1 MiB per file, and 32 MiB total source. Eligibility covers `next.config.js/mjs/cjs/ts`, App Router `route.js/ts`, and JavaScript/TypeScript Pages API handlers. A dependency/config marker is required for Next.js applicability. The engine uses one worker, a five-second per-rule timeout, a 512 MiB engine memory setting, and the scanner/assessment deadline (five-minute adapter fallback). Only local embedded rules are loaded; metrics/version checks are disabled. Project ignore files and `nosem` comments cannot silently suppress this dedicated pack's selected targets.

The report retains only known rule IDs, fixed review descriptions, relative source locations, severities/CWEs, and snapshot metadata. Matched values, raw Semgrep results, source excerpts, and raw tool stdout/stderr are not retained. A sealed `source-manifest.json` records copied relative paths, sizes, SHA-256 file/rule digests, acknowledged scanned count, and diagnostic/skip counts. Raw output and the copied source are removed with the private workspace; a cleanup failure is reported explicitly rather than silently claiming success. Treat source paths/digests and assessment artifacts as sensitive metadata.

Incomplete inventory, skipped/unacknowledged files, engine errors, nonzero exit, cancellation, malformed reports, and zero acknowledged targets cannot produce a clean result. Valid normalized findings survive a failed engine as sealed partial evidence. Tests reject unknown rule IDs, source paths outside the selected snapshot, malformed result schemas, and source-manifest tampering.

## Pinned framework acceptance

The [production Next.js lab](../test/nextjs-lab/README.md) now builds vulnerable and patched counterparts with lockfile-pinned Next.js 16.4.3 and React 19.3.1. Its measured 2026-11-04 baseline passes all 22 framework checks: production source-map exposure and bounded embedded-source decoding, HTML/Pages JSON access, real App Router RSC access for both anonymous and reader identities, real rendered Server Action references and dispatch, built-in origin rejection, controlled cache reset, paired redirects, and fresh callback correlation. The cache/proxy fixtures exercise controlled application behavior within Next.js; they do not claim an external CDN or built-in image-optimizer vulnerability.

RSC acceptance captures the pinned framework's canonical same-origin resource URL from its cache-busting redirect without following it, then supplies that exact URL to the native comparisons. The real App Router page has an owner baseline for each denied identity. The patched counterpart authorizes before rendering through its Next.js proxy and returns 403. An HTTP 200 streamed error without a private marker remains unknown rather than being counted as proven denial. This gate does not implement browser navigation or a flight decoder.

An optional real-Chromium gate adds owner, reader, and anonymous discovery against both counterparts. The measured 2026-11-04 browser baseline passes 46/46 total checks. It exercises delayed client hydration, a lazy-imported module's API request, client-side App Router navigation with an observed RSC request, identity-bound encrypted replay, credential redaction, form inventory without submission, and a blocked synthetic write verified by server counters. The recorder waits for one second of network quiet within its existing per-page deadline; later timers and arbitrary interactions remain outside that guarantee. Idle deadline failures and excluded writes retain partial coverage. DOM forms are attributed to the final rendered URL after navigation; excluded rendered documents are omitted and reported as partial coverage. DOM inventory/evaluation failures are also explicit partial coverage. The browser version is recorded separately from the pinned framework versions. Multipart acceptance observes an actual Next.js browser form submission containing a synthetic binary file. An owned loopback proxy captures the original HTTP body and prevents that observation POST from reaching the action. The native finite campaign then replays those exact bytes for owner, reader, anonymous, and disallowed-Origin cases, proving state and reset independently. The vulnerable fixture yields the expected identity violations and the patched fixture denies them; both keep the built-in origin guard. These four additional browser-dependent rows use actual native request receipts; origin rows share their respective campaigns to avoid double-counting. Observation traffic is not counted as active security testing. Login acceptance also covers a real React-controlled fetch login, path-scoped HttpOnly sessions for owner and reader, wrong-password rejection, anonymous session isolation, and login workspace cleanup. Cookie capture uses the protected URL's path and refreshes cookies/storage after verification. Login rows explicitly mark their HTTP request counts as untracked; scorecard request sums are lower bounds. These are synthetic same-origin sessions, not a complete external-provider or Auth.js integration. CI enables these browser gates; no remote CI run is claimed here.

The source rule pack was exercised with the runtime-pinned Semgrep 1.178.0 in a network-disabled, read-only container against eight intended matches spanning all six rule IDs and separate negative controls. A targeted GitHub Actions workflow repeats the real source-engine and production-framework gates for relevant changes. The lab driver binds only owned subprocesses to loopback and shuts down those subprocesses after the run. It does not modify the running dashboard or existing containers.

These are a reproducible version-pinned fixture baseline, not a universal recall/precision claim. They do not cover every framework version, production reverse proxy, browser workflow, or deployment platform. No production application scan was performed.

## Deliberate remaining gaps

This release implements deeper read discovery, exposure checks, and controlled access comparisons. It does not complete every phase of the broader roadmap:

- Server Action tests use only explicit finite campaigns and exact observed bodies. Automatic action-ID discovery, multipart body generation, argument mutation, and arbitrary action invocation remain unsupported. Existing API write/fuzz jobs retain their independent approvals.
- Cache and URL probes are limited to explicit controlled fixtures. Arbitrary cache poisoning headers, automatic cache invalidation, private-network enumeration, unreviewed callback services, and SSRF exploitation chains are not implemented.
- No complete App Router flight decoder, invented dynamic route values, unbounded source-map analysis or external section retrieval, full mapping-to-original-line decoding, or authenticated asset fetches.
- Source checks use the bounded bundled pack and existing generic adapters. Complete program analysis, automatic dependency/version reconciliation across source and deployment, dynamic config evaluation, and full client/server-boundary analysis remain outside the native pack.

## Validation

Go HTTP fixtures also exercise cold/fill/warm/bypass cache controls, failed/ineffective resets, cross-representation disclosure, cache attribution limits, paired redirects without following them, fresh/stale/wrong callback events, missing callbacks, collector credential isolation, native boundary executor routing, scope/exclusion/guard failures, and manifest tampering. They exercise one-shot action authorization/origin violations, allowed-state baselines, ineffective and failed cleanup, interrupted writes, replay refusal, manifest tampering, native executor routing without an OpenAPI schema, and discovery, exclusions, per-URL DNS-aware guards, cancellation, request/endpoint/byte caps (including interrupted transfers), adjacent maps, source-map negative controls, real and invalid private-key material, anonymous isolation, HTML/JSON/RSC allow/deny behavior, wrong content types, missing baselines, session expiry, and executor integration. Planning tests cover profile selection, custom-selection precedence, and limit fingerprints; HTTP handler tests cover profile persistence and typed-assessment requirements.

The deterministic protocol fixtures and pinned production-framework acceptance complement each other. External identity providers/MFA, arbitrary interactive controls, representative external CDN/proxy deployment matrices, and broader version coverage remain roadmap items. No external application scan is part of implementation validation.

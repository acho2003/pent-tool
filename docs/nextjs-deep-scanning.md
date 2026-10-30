# Next.js deep assessments

Choose **Next.js deep** as the web profile in a typed Web Application or API assessment. Preview the generated plan before starting it. The profile is also available for typed schedules. Existing saved plans need a fresh preview because registry version 18 changes planning semantics.

The profile selects the native `nextjs-assets` adapter and native resource checks alongside the ordinary applicable scanners. Explicit custom scanner selections take precedence. Optional scanners still need to be selected, and unavailable external tools remain visible gaps. Selecting the profile does not change scope or enable the opt-in unified workflow.

## What this release adds

- HTML parsing for script/module/preload references, including single-quoted attributes, base paths, and query strings.
- Bounded traversal of explicit page links and literal Next.js chunk references. App Router bootstrap references can supply asset URLs; this is not a complete flight protocol parser.
- API URL strings from pages and bundles as unverified inventory candidates. These strings do not cause speculative API requests. Observed browser requests continue through the existing inventory workflow.
- Adjacent `.map` probes when a script has no explicit map reference. Source-map findings require top-level version 3 and typed sources/mappings evidence, rather than a successful status alone.
- Local validation of unencrypted PEM private keys in anonymous pages, scripts, and the bounded source-map prefix. Values, excerpts, and key-derived fingerprints are not retained or used against other services. Public configuration names alone do not produce secret findings.
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

Pages are parsed up to 512 KiB and scripts up to 2 MiB. Map probes inspect only their first 4 KiB. Response parsing limits and failed requests are reported; reaching a limit is not evidence of a clean application. Literal route candidate inventory is bounded to 500 entries. Native discovery remains anonymous, does not submit forms, follows no redirects, and never forwards configured target or global credential headers to assets. Existing verified browser discovery supplies authenticated observations when that workflow is enabled.

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

Supply an observed `Next-Action` header ID (40–64 hexadecimal characters), the exact action URL, and its exact request body. Header-based actions using `text/plain` or `application/x-www-form-urlencoded` are supported. Request and optional cleanup bodies are uploaded as immutable private fixture references, each bounded to 64 KiB. The form saves a manifest reference rather than placing arguments or state markers into the assessment record.

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

## Deliberate remaining gaps

This release implements deeper read discovery, exposure checks, and controlled access comparisons. It does not complete every phase of the broader roadmap:

- Server Action tests use only explicit finite campaigns and exact observed bodies. Multipart action bodies, automatic action-ID discovery, argument mutation, and arbitrary action invocation remain unsupported. Existing API write/fuzz jobs retain their independent approvals.
- Cache and URL probes are limited to explicit controlled fixtures. Arbitrary cache poisoning headers, automatic cache invalidation, private-network enumeration, unreviewed callback services, and SSRF exploitation chains are not implemented.
- No complete App Router flight decoder, invented dynamic route values, full source-map download/analysis, or authenticated asset fetches.
- Source-code, dependency, and general DAST checks continue through the existing applicable adapters. No new Next.js-specific SAST rules are bundled here.

## Validation

Go HTTP fixtures also exercise cold/fill/warm/bypass cache controls, failed/ineffective resets, cross-representation disclosure, cache attribution limits, paired redirects without following them, fresh/stale/wrong callback events, missing callbacks, collector credential isolation, native boundary executor routing, scope/exclusion/guard failures, and manifest tampering. They exercise one-shot action authorization/origin violations, allowed-state baselines, ineffective and failed cleanup, interrupted writes, replay refusal, manifest tampering, native executor routing without an OpenAPI schema, and discovery, exclusions, per-URL DNS-aware guards, cancellation, request/endpoint/byte caps (including interrupted transfers), adjacent maps, source-map negative controls, real and invalid private-key material, anonymous isolation, HTML/JSON/RSC allow/deny behavior, wrong content types, missing baselines, session expiry, and executor integration. Planning tests cover profile selection, custom-selection precedence, and limit fingerprints; HTTP handler tests cover profile persistence and typed-assessment requirements.

These are deterministic protocol fixtures, not a claim that every current Next.js version or deployment has been tested. Pinned real-framework browser/container benchmarks remain a roadmap item. No external application scan is part of implementation validation.

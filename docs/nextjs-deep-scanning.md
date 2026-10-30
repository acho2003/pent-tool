# Next.js deep assessments

Choose **Next.js deep** as the web profile in a typed Web Application or API assessment. Preview the generated plan before starting it. The profile is also available for typed schedules. Existing saved plans need a fresh preview because registry version 17 changes planning semantics.

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

## Deliberate remaining gaps

This release implements deeper read discovery, exposure checks, and controlled access comparisons. It does not complete every phase of the broader roadmap:

- Server Action tests use only explicit finite campaigns and exact observed bodies. Multipart action bodies, automatic action-ID discovery, argument mutation, and arbitrary action invocation remain unsupported. Existing API write/fuzz jobs retain their independent approvals.
- No shared-cache contamination or image/proxy SSRF probes. Unauthorized controlled-resource access may reveal a cache-related problem, but the scanner does not infer the root cause from a response difference.
- No complete App Router flight decoder, invented dynamic route values, full source-map download/analysis, or authenticated asset fetches.
- Source-code, dependency, and general DAST checks continue through the existing applicable adapters. No new Next.js-specific SAST rules are bundled here.

## Validation

Go HTTP fixtures exercise one-shot action authorization/origin violations, allowed-state baselines, ineffective and failed cleanup, interrupted writes, replay refusal, manifest tampering, native executor routing without an OpenAPI schema, and discovery, exclusions, per-URL DNS-aware guards, cancellation, request/endpoint/byte caps (including interrupted transfers), adjacent maps, source-map negative controls, real and invalid private-key material, anonymous isolation, HTML/JSON/RSC allow/deny behavior, wrong content types, missing baselines, session expiry, and executor integration. Planning tests cover profile selection, custom-selection precedence, and limit fingerprints; HTTP handler tests cover profile persistence and typed-assessment requirements.

These are deterministic protocol fixtures, not a claim that every current Next.js version or deployment has been tested. Pinned real-framework browser/container benchmarks remain a roadmap item. No external application scan is part of implementation validation.

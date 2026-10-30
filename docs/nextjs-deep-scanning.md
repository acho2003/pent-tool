# Next.js deep assessments

Choose **Next.js deep** as the web profile in a typed Web Application or API assessment. Preview the generated plan before starting it. The profile is also available for typed schedules. Existing saved plans need a fresh preview because registry version 16 changes planning semantics.

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

## Deliberate remaining gaps

This release implements deeper read discovery, exposure checks, and controlled access comparisons. It does not complete every phase of the broader roadmap:

- No arbitrary Server Action invocation or action-specific authorization fuzzing. Existing explicitly approved API write/fuzz jobs keep their own fixture, journal, repetition, and cleanup constraints.
- No shared-cache contamination or image/proxy SSRF probes. Unauthorized controlled-resource access may reveal a cache-related problem, but the scanner does not infer the root cause from a response difference.
- No complete App Router flight decoder, invented dynamic route values, full source-map download/analysis, or authenticated asset fetches.
- Source-code, dependency, and general DAST checks continue through the existing applicable adapters. No new Next.js-specific SAST rules are bundled here.

## Validation

Go HTTP fixtures exercise discovery, exclusions, per-URL DNS-aware guards, cancellation, request/endpoint/byte caps (including interrupted transfers), adjacent maps, source-map negative controls, real and invalid private-key material, anonymous isolation, HTML/JSON/RSC allow/deny behavior, wrong content types, missing baselines, session expiry, and executor integration. Planning tests cover profile selection, custom-selection precedence, and limit fingerprints; HTTP handler tests cover profile persistence and typed-assessment requirements.

These are deterministic protocol fixtures, not a claim that every current Next.js version or deployment has been tested. Pinned real-framework browser/container benchmarks remain a roadmap item. No external application scan is part of implementation validation.

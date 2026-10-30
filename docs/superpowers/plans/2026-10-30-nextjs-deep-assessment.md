# Next.js deep assessment plan

Date: 2026-10-30
Status: Read discovery, controlled resource comparisons, finite Server Action campaigns, and controlled cache/redirect/callback probes implemented; remaining roadmap items are listed in [Next.js deep assessments](../../nextjs-deep-scanning.md). No target scan was performed.

## Objective

Increase reproducible, actionable findings on authorized Next.js applications by discovering more application behavior and testing security boundaries across identities and response formats. Measure verified issue recall and coverage, rather than raw alert count or request volume.

## Current foundation

- `internal/scanner/nextjs_assets.go` detects Next.js, fingerprints a served runtime version, matches an embedded advisory snapshot, probes referenced source maps, and inventories Pages Router build-manifest routes.
- It fetches assets anonymously, examines at most 40 scripts, records at most 500 manifest routes, and confirms at most 100 routes. App Router flight data is currently a detection signal rather than a discovery parser.
- Dynamic manifest routes remain unmaterialized without supplied values. Source-map confirmation reads only 4 KiB and retains no map content.
- `identity_discovery.go`, `authorization_comparisons.go`, the request gateway, budgets, and coverage artifacts provide reusable infrastructure. Existing authorization comparisons require supplied controlled read resources and verified identities.
- Expanded discovery is opt-in under the unified workflow. New capabilities must declare that dependency or work through the existing typed assessment path; they must not silently enable the expanded workflow.

## Delivery sequence

### 1. Next.js surface discovery — highest priority

Extend the asset adapter or extract a dedicated discovery module:

- Parse script references with an HTML parser; support base paths, asset prefixes, single-quoted attributes, module scripts, and observed lazy-loaded chunks.
- Collect scoped links, concrete API calls, route parameters, Pages Router data requests, and App Router/RSC requests from browser traffic and bounded asset analysis.
- Treat chunk strings and serialized flight data as candidate evidence, not authoritative route manifests. Validate supported parser formats against pinned framework fixtures.
- Materialize dynamic routes only from observed links, supplied resource fixtures, or known test data. Preserve unresolved templates visibly.
- Run discovery separately for anonymous and supplied verified identities. Keep credentials bound to their approved origin, including when assets use a CDN.
- Store provenance, method, response representation, parameter/body schema, identity, and discovery confidence. Feed eligible concrete requests back into the existing assessment scheduler.

Acceptance: lab routes absent from the landing page become discoverable; dynamic values are never invented; unsupported formats and truncation produce explicit gaps; out-of-scope assets are not fetched.

### 2. Protected data and authorization checks — highest finding value

Extend controlled-resource comparisons beyond the current API-only GET path:

- Compare anonymous, user A, user B, and privileged identities where supplied.
- Test observed HTML, Pages Router JSON, RSC/flight representations, and read API endpoints independently. A denied page does not establish that its data representation is denied.
- Use owned-resource fixtures and expected allow/deny markers to detect cross-user access, role violations, and sensitive serialized data exposure.
- Verify that an expected allow identity can retrieve the resource before accepting an unexpected allow as evidence.
- Distinguish sensitive fields from normal public page data. An RSC response, action identifier, route name, or HTTP 200 is not itself a vulnerability.

Acceptance: positive controls prove the intended resource; login pages and soft-404s cannot trigger findings; authenticated comparisons use isolated sessions and recheck session validity.

### 3. Server Actions and route-handler testing

- Inventory observed action calls, their serialized inputs, content type, identity, and route. Do not guess action IDs or classify every POST as an action.
- Add source-assisted checks for authorization, input validation, unsafe redirects, and sensitive data crossing server/client boundaries.
- Exercise action authentication, resource ownership, origin enforcement, and input validation only through explicitly approved operations and controlled fixtures.
- Integrate with the existing write approval and cleanup machinery. An approved one-shot write does not authorize repeated fuzzing; repeated tests require an operation-specific execution allowance and reset strategy.
- Report untested actions as coverage gaps, with the missing fixture or execution allowance.

Acceptance: an instrumented lab proves exactly which action executed and which state changed; cleanup failure stops dependent tests; the scanner cannot replay an unapproved action.

### 4. Assets, configuration, and dependency evidence

- Add bounded probes for unreferenced adjacent source maps and publicly exposed development/debug artifacts, with content validation and soft-404 controls.
- Offer separately configured source-map analysis to extract endpoint candidates and detect potential secrets. Redact evidence, cap decompression and parsed content sizes, and do not validate discovered credentials against external services.
- Treat public client configuration and `NEXT_PUBLIC_*` names as context; only actual sensitive values or behavior justify escalation.
- When source is supplied, inspect Next.js configuration, route handlers, Server Actions, environment-variable use, and server-only imports through the existing source scanners.
- Use lockfiles/SBOMs for exact dependency versions when available; preserve conflicts with observed runtime evidence.
- Refresh advisory data through the existing snapshot updater and review range parsing, prereleases, withdrawn advisories, and patch recommendations. Keep version matches distinct from behaviorally verified vulnerabilities.

Acceptance: harmless source maps remain low severity; genuine secrets are redacted and triaged; unknown framework versions never imply a clean advisory result.

### 5. Cache, redirects, and image/proxy boundaries

- Compare controlled synthetic responses across identities and observed HTML/data representations for private-data leakage through caching.
- Check cache headers and representation handling as signals; require a synthetic private marker reaching an unauthorized identity before confirming data leakage.
- Test redirect parameters using an approved benign destination and paired controls.
- Test observed image/proxy URL inputs using an explicitly supplied callback service. Do not probe private networks or cloud metadata as a default.
- Run cache-isolation tests in a dedicated environment or isolated namespace; shared-cache contamination needs an explicit test procedure and cleanup plan.

Acceptance: personalized-response differences alone do not produce cache findings; callback observations are correlated to individual checks; redirect and callback scope are enforced at every hop.

### 6. Deep profile, scheduling, and reporting

- Add a `nextjs-deep` profile that composes existing scanners with the native checks above; avoid creating a competing pipeline.
- Make page, asset, request, byte, identity, per-endpoint mutation, concurrency, and wall-time limits configurable and fingerprinted.
- Prioritize protected data paths, observed inputs, authentication boundaries, and unique handlers before duplicate assets or low-value header checks.
- Preserve existing scope and execution approvals. A deeper profile increases test selection within those approvals.
- Record per-check states: eligible, attempted, verified, negative control passed, failed, skipped, and unknown. Discovery traffic must not count as active security testing.
- Deduplicate by root cause and affected security boundary while retaining endpoint and identity evidence. Separate confirmed behavior, version matches, suspected exposures, and informational observations.

Acceptance: every coverage claim links to request/check evidence; budget exhaustion produces partial results; cancellation and restart do not lose sealed findings or duplicate approved writes.

## Validation and release gates

Build pinned vulnerable/patched fixtures spanning Pages Router and App Router, anonymous and two-user sessions, dynamic routes, base paths, lazy chunks, RSC streaming, observed actions, and representative reverse-proxy/cache behavior. Include soft-404s, session expiry, network failures, oversized assets, malformed maps, and deliberately public data as negative controls.

For each check, require a vulnerable fixture detected, a patched fixture passing, and a precise evidence assertion. Measure discovery recall, confirmed finding recall, false positives, requests per verified finding, and explicit coverage gaps. Set numeric recall targets after measuring the baseline; require all mandatory known-positive fixtures and zero false positives on mandatory negative controls before release.

Release discovery and read-only comparisons first, then asset/source correlation, then action and cache tests after their fixture and execution controls pass. Validate Go changes with focused scanner tests and the repository-required Go checks; run container/browser acceptance for cross-process behavior and UI checks for any new profile or coverage controls. No production scan is required to validate the implementation.

## Reference model

- Next.js authentication guidance: https://nextjs.org/docs/app/guides/authentication
- Next.js data security: https://nextjs.org/docs/15/app/guides/data-security
- Server-side function security: https://nextjs.org/docs/app/api-reference/directives/use-server
- Browser source maps: https://nextjs.org/docs/pages/api-reference/config/next-config-js/productionBrowserSourceMaps

Next.js documents multiple application entry points and recommends authorization close to data access. This motivates independent checks of pages, data responses, APIs, and actions rather than assuming page-level protection covers every entry point.

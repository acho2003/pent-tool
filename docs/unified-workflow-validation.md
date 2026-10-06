# Unified workflow validation

These results cover the implemented adapters and evidence pipeline. They do not
establish that the complete expanded workflow is ready for default rollout.
`XALGORIX_UNIFIED_WORKFLOW` remains disabled by default.

## Passed checks

- `CGO_ENABLED=0 go test ./...` passed on the development machine.
- `go test -race ./internal/scanner -run 'TestGateway|TestGraphQL|TestProof|TestAcceptedRevision'` passed.
- `npm --prefix webui run build` passed, including TypeScript checking. The build
  still reports the existing bundle-size warning.
- Native Linux arm64 application-only Docker build succeeded under the temporary
  `xalgorix:workflow-validation` tag using the retained Debian slim runtime.
- Offline retained-runtime smoke test passed: executable versions, Chromium,
  libraries, JavaScript/HTTP discovery, source fixture, and removed-tool checks.
- Native Chromium fixture captured authenticated XHR and repeated query values,
  followed an allowed link, recorded forms, and blocked excluded/write routes.
- A disposable dedicated ZAP on an internal Docker network passed native request
  recording, GET/HEAD variants, two approved origins, filtered OpenAPI/GraphQL
  imports, and proxy restoration. Vulnerability rules were disabled in this
  routing fixture; it makes no executed-check or vulnerability-detection claim.
- Native Nuclei listed 9,966 HTTP templates under the configured policy. This is
  an enabled-template inventory, not proof that those checks executed.
- Existing Greenbone returned GMP version 22.7 to a read-only `<get_version/>`
  request. No credentials, scan task, feed update, or volume modification was
  involved in that check.
- Unit fixtures cover 684 request manifest dispositions, Wapiti batching beyond
  50 inputs, immutable approvals, scope isolation, HTTP/TLS recording, exact
  body variants, encoded query identity, GraphQL input materialization,
  malformed artifacts, redaction, and coverage-count drill-down consistency.

## Remaining acceptance

- End-to-end UI acceptance for the newly added browser storage/access-test controls.
  Native worker tests pass for local/session storage, protected-route markers,
  anonymous controls, origin isolation and encrypted credential storage.
- Approved URL-encoded POST fuzzing with explicit bounded operation approval and
  cleanup; existing single-write approvals must keep their original semantics.
- End-to-end process restart during discovery/approval and native scanner execution.
  Per-job disk checkpoint/reload, interrupted-attempt retry, sealed completion reuse,
  and checkpoint failure refusal now pass deterministic executor acceptance.
- The complete 684-request execution fixture across retained active adapters;
  manifest coverage alone is insufficient.
- Bounded, explicitly approved state-changing scanner routing; encrypted exact
  replay and captured read-only GraphQL POST routing are implemented.
- Supplemental ZAP spider results merged into the inventory before active checks;
  structured runs currently disable that spider to preserve the request boundary.
- End-to-end native multi-role workflow acceptance across all retained active
  scanners. Named-role browser discovery, previewed scanner jobs, independently
  renewed credentials, and exact role receipt attribution are implemented.
- Enforcement of the recording boundary for adapters that can bypass proxies,
  and secret sanitization at native capture time. Saved JSON, JSONL, XML and text
  artifacts now mask common unknown credentials before public availability;
  native subprocesses still create their private raw output before sanitization.
- End-to-end browser UI approval/authentication/report acceptance and amd64 CI.

Production containers, data volumes, credentials, Greenbone feeds, and unrelated
projects were preserved. No global Docker pruning or public-target scanning was
performed. The disposable validation network and daemon may be removed after
validation; the validation tag remains available for review.

Follow-up validation: the assessment executor fixture routes 684 selected Wapiti query inputs through 14 batches with unique submission IDs. Native arm64 Chromium fixtures capture authenticated XHR and read-only GraphQL POST body metadata, block mutations/forms/logout, and verify an explicit one-request budget. The disposable native ZAP request/import fixture passes again. These are submission/discovery checks, not proof that every native active check completed.

## October 6 continuation

Six implementation commits retain accepted executor versions, remove the expanded
Wapiti selection ceiling, bound evidence by complete records, expose gateway
limits, preserve explicit OpenVAS ports, capture read-only GraphQL POST requests,
preview active discovery actions, and add encrypted browser storage/access tests.

The 684-input assessment fixture now inspects the fake scanner process's received
`-u`/`--start` arguments as well as unique submission records. All 684 distinct
inputs reach 14 bounded batches; this is not native vulnerability-check proof.
The full Go suite, scanner/credential race tests and Web UI build pass. Native
Chromium verifies protected markers, anonymous controls and storage-origin
isolation; the disposable native ZAP request/import fixture also passes.

A fresh application-only Linux arm64 image is available as
`xalgorix:workflow-validation-a250ade`, with application revision
`a250ade7789f051eac9858966f9fe926a73f805b`. Its offline scanner/runtime smoke test
passed. This reuses the existing slim runtime and is not a full scanner rebuild
from scratch. Production application/service containers were not replaced.
The expanded feature flag remains disabled by default while the remaining
acceptance and implementation work above is outstanding.

After validation, the disposable `xalgorix-workflow-zap` container and
`xalgorix-workflow-validation` network were removed. Both validation image tags
remain available. Production services, other images and all volumes were preserved.

Encrypted replay follow-up: credential isolation/integrity, exact URL/body variants, missing-key fail-closed routing, public-manifest redaction and captured read-only GraphQL gateway tests pass. The full Go suite, scanner/credential race tests and Web UI build pass. Native arm64 Chromium restores captured GraphQL bodies and verified headers from encrypted replay while public discovery artifacts omit secrets. Native ZAP body/HTTPS acceptance now passes (see below).

ZAP inventory acceptance: structured assessments no longer issue separate root or API seeds, and schema imports are filtered to selected inventory requests. A disposable native arm64 ZAP fixture acknowledges all 684 request variants and verifies saved HTTP seeding receipts for every inventory ID, including repeated query parameters, HEAD, multiple approved origins and a read-only GraphQL JSON POST over HTTPS. Native vulnerability rules are disabled in this routing fixture; it does not prove active-check completion. The full Go suite passes.

Variant-policy acceptance: method/body variants at one URL consume separate request budget slots; exhausted variants have explicit skip reasons. Tests prevent unapproved browser form submission, inferred authentication on DOM aliases and replay of redacted URLs. Native arm64 Chromium confirms form-action secret redaction and encrypted GraphQL replay. Full Go and scanner/credential race checks pass.

Write restart acceptance: changing attempt directories cannot replay an approved write. Thirty-two independently opened journals retain all intents; four concurrent processes admit exactly one intent for the same operation. Prior attempt journals migrate with their recorded states, and corrupt or unresolved records refuse automatic resume. Discovery approval leaves the parent unchanged and clears mutation consent in the child. Full Go and race checks pass; native Linux arm64 repeats the journal, retry, migration and replay fixtures successfully.


## Live UI and native request routing regressions

A disposable internal-network lab and application instance exercised dashboard
login, encrypted target credentials, the immediate Chromium protected-route test
with an anonymous negative control, assessment preview/start, authenticated
browser discovery, endpoint evidence traces, per-tool stop, and PDF download.
The fixture used only synthetic credentials and local destinations. Its ZAP
active rules were disabled; this UI check does not establish active-check coverage.

The live fixture exposed an empty-collection Scan Details crash and a premature
terminal failure event after per-tool stop. Commits `f8a9c5d` and `31aeb92` fix
those regressions. Commit `ddad363` redacts credential aliases and SPA route
metadata without modifying the runtime inventory. Commit `6ebef13` preserves
nonsecret authentication contexts in scanner inputs and prevents an authenticated
HTTP receipt from proving exercise of an anonymous or different-role variant.

Native arm64 Wapiti now produces HTTP receipts for all **684 selected variants in
14 batches**. Native Nuclei produces HTTP receipts for all **684 variants** with
one locally generated, signed deterministic fixture template. The normal
unsigned-template restriction remains enabled, and fixture signing trust is
never added to the runtime image or the user's key store. Neither result proves
that the full retained vulnerability template/module inventory executed.

The expanded workflow still requires the remaining implementation and acceptance
items listed above; the production feature flag remains disabled by default.

The bounded native Dalfox failure fixture retains 12 HTTP receipts and explicit
per-request timeout dispositions for the remaining selected inputs. It does not
claim all 684 were exercised. Linux process-group cancellation reduces the
helper-stop regression from ten seconds to about 50 ms, while preserving
`TIMEOUT`/`CANCELLED` execution independently from artifact parser failures.
The full Go suite and scanner/credential race checks pass for these changes.

Approval endpoint regression acceptance now covers a fresh server reading the
same data directory before and after approval: pending previews retain their
fingerprint, stale approval returns HTTP 409, accepted revisions survive restart,
and the original parent plan remains unchanged. Execution restart/resume and
complete staged UI approval acceptance remain separate outstanding checks.

The application-only arm64 validation image `xalgorix:workflow-validation-6d8fe6b`
contains application revision `6d8fe6b9306561f76faab695246bba7b98817a4f` and measures
1,139,410,181 bytes. Its offline runtime smoke test passes all 24 retained scanner
commands, Chromium/discovery, libraries, and source fixtures. This reuses the
existing slim runtime; no reclaimed-space claim or production replacement was
made.

## Supplied role authorization expectations

Named identities are verified independently and keep separate renewal callbacks,
headers, and browser storage. Default discovery and general scanner adapters
still use the primary identity; this does not establish discovery coverage for
all roles.

Expanded native API checks now consume `authorization_expectations` and saved
resource fixtures. A fixture is JSON with an exact `url` and a bounded
`response_marker`, uploaded through the existing API fixture route. Its URL must
match a materialized GET operation on the original authenticated target origin.
Each expectation requires a separately verified identity and a selected inventory
request. No IDs or business values are invented. A deny-role access finding
requires both that role and the expected allow role to return the supplied marker
for the same controlled resource. Generic 200 responses, redirects, expired
credentials and missing fixtures remain explicit gaps.

Saved results contain status, response digest, nonsecret context/request IDs and
coverage event references. Response bodies and credentials are not saved. The UI
and downloadable report consume the same saved comparison results; reports make
no target requests. Local fixtures cover first-attempt executor routing, safe and
vulnerable role access, credential isolation, excluded/wrong-target/write inputs,
unknown responses, persistence and report URL redaction. Full Go tests, targeted
scanner race tests and the Web UI typecheck/build pass. Expanded role execution
remains behind the unified-workflow flag, which remains disabled by default.

The setup UI now saves multiple named identities on one target without replacing
other identities. Verification results and checkpoint edits are keyed by the
credential reference. Operators can save a controlled GET resource and paired
allow/deny expectations through the existing fixture upload route. Removing an
identity clears expectations that would otherwise become stale. A local
Playwright fixture verifies two saved credentials, an independent immediate test,
the paired expectations in the preview payload, and removal isolation. This UI
fixture uses mocked API responses and is separate from native execution tests.
The full Go suite and Web UI typecheck/build pass.

Artifact integrity follow-up: shared process adapters, ZAP, Vuls and OpenVAS no
longer ignore artifact redaction errors. Failed redaction removes the public
artifact reference, records parser incompleteness, and preserves timeout or
cancellation independently. Redaction replacement is atomic and private. Bounded
Vuls reports retain whole CVE entries; bounded Greenbone XML retains whole native
result elements, native IDs and metadata. Both report partial evidence explicitly
instead of byte-truncating JSON or XML. Local parser fixtures, the full Go suite,
and targeted scanner race checks pass. This does not establish sanitization of
all unknown credentials in every native artifact format.

Additional identity browser discovery is now isolated by Chromium profile,
verification callback, storage and encrypted replay context. Native Linux arm64
fixtures confirm two roles produce distinct variants of the same authenticated
XHR endpoint and cannot read each other's replay record. Saved discovery runs
include context, identity, role, attempt and plan metadata. UI/report counts use
only observations linked to that attempt's artifact. Failed identities never
inherit the primary session. General adapters retain explicit skipped dispositions
for named-role requests until per-role routing is implemented; primary scanner
completion cannot credit those requests. Full Go, Web UI build, and native arm64
Chromium/scanner race checks pass. The original first-attempt executor fixture
now asserts matched role outcomes, rather than only counting returned results.

Browser workers now publish identified live start/final events and register their
cancellation callbacks with the existing per-tool stop registry. Named workers
carry role labels in live scan details. User cancellation and deadline exhaustion
produce separate structured execution outcomes while preserving partial discovery
artifacts. Native arm64 Chromium race fixtures verify authenticated XHR, storage
checkpoints, separate identity replay, and stopping a registered browser attempt
with callback cleanup and a matching terminal event. The full Go suite and Web UI
build pass. These checks use only disposable local fixtures.

The updated application-only Linux arm64 validation image is
`xalgorix:workflow-validation-0c6c975`, revision
`0c6c975585485a754d915af6c9ec922ae77f8a18`, measuring 1,147,720,031 bytes.
Offline smoke checks passed all 24 required scanner commands, Chromium,
HTTP/JavaScript discovery, native/Python libraries and source fixtures. The
fixture HTTP server logged a benign connection reset from a closed probe; the
smoke process completed successfully. The image reuses the retained slim runtime;
it is not a full toolchain rebuild and no disk reclamation was performed.
Disposable browser sessions and fixture containers were closed/removed. The
validation tag remains available; production images, services and volumes remain
unchanged. Expanded workflow rollout is still blocked by the outstanding items
in Remaining acceptance, especially approved POST fuzzing, supplemental ZAP
inventory discovery, general per-role adapter routing, complete execution restart
acceptance and amd64 CI. No completeness percentage is inferred from these tests.

## Per-job recovery and role routing follow-up

Commits `f04f6df` and `3748689` add format-aware common credential redaction and
per-job workflow checkpoints. JSON and XML stay parseable, large integer/native
IDs survive, malformed structured output fails closed, and empty JSONL remains
valid for a no-finding scan. A disk-reload fixture starts a fresh executor after
cancellation: the sealed completed attempt is reused, the interrupted attempt
gets a fresh ID, and pending work executes. Checkpoint failure stops subsequent
execution. Partial native evidence cannot produce a clean completed stage.

Registry version 10 previews separate authentication, Nuclei, ZAP, Wapiti and
Dalfox jobs for additional named identities. Their prerequisites, input selection,
verification/renewal and saved receipts stay isolated. Resolved approved GET/HEAD
schema operations receive role-specific seeds; those seeds are not observations
or proof of a live host. External origins, unresolved inputs and write operations
are not promoted. The primary identity preserves legacy inventory IDs.

The full Go suite, scanner/credential race tests, Web UI typecheck/build and Linux
arm64 race fixtures pass. A disposable local HTTP gateway verifies that a reader
credential reaches its own request and its response cannot credit admin or
anonymous variants. No public targets or production containers were used. The
expanded flag remains disabled pending the Remaining acceptance items; these
checks do not establish complete native active-check or staged UI acceptance.

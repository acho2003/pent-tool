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
- Complete staged workflow restart/resume acceptance, including approval pauses.
- The complete 684-request execution fixture across retained active adapters;
  manifest coverage alone is insufficient.
- Bounded, explicitly approved state-changing scanner routing; encrypted exact
  replay and captured read-only GraphQL POST routing are implemented.
- Supplemental ZAP spider results merged into the inventory before active checks;
  structured runs currently disable that spider to preserve the request boundary.
- Multi-role discovery/authentication contexts; the native HTTPS ZAP gateway
  fixture now covers 684 method/body-aware request submissions.
- Evidence sanitization before persistence across all native artifact formats and
  enforcement of the recording boundary for adapters that can bypass proxies.
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

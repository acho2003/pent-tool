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
- Complete staged UI/native acceptance of approved form campaigns inside a full
  assessment; the isolated native Wapiti campaign now passes exact-body, budget,
  cleanup and replay refusal checks.
- End-to-end process restart during discovery/approval and native scanner execution.
  Per-job disk checkpoint/reload, interrupted-attempt retry, sealed completion reuse,
  and checkpoint failure refusal now pass deterministic executor acceptance.
- The complete 684-request execution fixture across retained active adapters;
  manifest coverage alone is insufficient.
- Bounded, explicitly approved state-changing scanner routing; encrypted exact
  replay and captured read-only GraphQL POST routing are implemented.
- Complete staged UI/native acceptance for supplemental discovery; its bounded
  read-only ZAP worker and inventory response/candidate extraction now pass the
  disposable arm64 daemon fixture.
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


## Supplemental ZAP discovery acceptance

A pinned disposable ZAP 2.17.0 daemon on an internal Docker network passed the
Linux arm64 race fixture `TestZAPRuntimeSupplementalDiscoveryIsReadOnlyAndFeedsInventory`
in 7.08 seconds. It discovers an unseeded HTML route with repeated query values,
records its HTTP 200 response in the shared inventory format, submits no POST
forms, blocks excluded and out-of-path requests, emits no active-test traffic,
and restores the original spider form policy. Unit fixtures preserve blocked
candidate dispositions and verify renewed gateway credentials. The full Go suite
and scanner/credential race tests pass. This is discovery/routing acceptance,
not a claim that native vulnerability checks completed for every endpoint.

## Approved form campaign acceptance (2026-10-06)

- Installed Wapiti 3.3.2 on native Linux arm64 passed the offline local fixture:
  original POST body receipt, cap of three POSTs, blocked excess payloads,
  declared DELETE cleanup, persistent campaign journal, and refused replay.
- Unit tests cover separate consent, production refusal, unsupported input
  semantics, atomic concurrent budgets, method/path/content-type isolation,
  body-free public manifests, and a process that produces no POST evidence.
- Playwright with synthetic API responses verified separate consent, unchanged
  fixture upload, body clearing, consent reset and removal of saved approval
  when leaving the test environment. This is UI acceptance, not a full server
  and native-scanner end-to-end run.
- Full Go suite, scanner/credential/assessment race checks and UI typecheck/build
  passed. Preview and execution reject forms whose semantics this installed
  Wapiti cannot preserve. Existing single-write consent remains separate.

## Process recovery and repeatable native acceptance

The executor now has a real OS-process termination fixture: one worker is killed
while its second job is running, then a fresh worker recovers from persisted
records. It reuses the first sealed result, executes the interrupted job again,
and completes the third job. Native Linux arm64 race checks pass this fixture.
This verifies executor process recovery; it does not substitute for restarting
a complete dashboard deployment during every approval and service stage.

Native Wapiti cancellation confirms that cleanup occurs after admitted POST
traffic drains and that cancelled campaign consent cannot be replayed. Native
Chromium identity/storage/cancellation tests and the complete Linux Web backend
race suite also pass. The backend suite mounts its checked-in legacy fixtures.

`runtime/workflow-acceptance.sh IMAGE SCANNER_TEST_BINARY WEB_TEST_BINARY` runs
these native fixtures against a built slim runtime. Compile the test binaries
with `go test -race -c` for the runtime architecture. It isolates HTTP fixtures
with Docker `--network none`, creates its own internal network for a pinned ZAP,
and removes only its own containers and network afterward. It runs the 684-input
Wapiti and deterministic signed Nuclei receipt fixtures, Dalfox's explicit
timeout-disposition fixture, Chromium, ZAP request/import/discovery, approved
form campaigns, process recovery and the Web backend race suite.

The existing amd64 Docker publication workflow now runs this acceptance script
after runtime smoke tests and before publication. It has not been dispatched
or verified on amd64 from this local session. Publication and default rollout
remain separate actions; this script does not enable the expanded feature flag.

A temporary application-only arm64 image, `xalgorix:workflow-validation-e69bc21`,
passed the offline runtime smoke test and has revision `e69bc21`. It measures
1,156,069,966 bytes and reuses the retained slim scanner runtime. This is not a
fresh rebuild of all scanners, a production replacement, or reclaimed disk space.

The reusable acceptance script passed end to end on native Linux arm64 with
revision `e69bc21`: signed Nuclei and Wapiti each recorded 684 exact-input HTTP
receipts, Dalfox recorded 12 receipts with explicit timeout dispositions for
remaining inputs, all five Chromium fixtures passed, approved POST and
cancellation fixtures passed, the full Web race suite passed, and the isolated
ZAP discovery and 684-request seeding fixtures passed. Its temporary service
containers and internal network were removed by the script. No full staged
assessment or undiscovered-asset completeness claim follows from these results.

## Staged acceptance suites

`runtime/staged-acceptance.sh IMAGE [APPLICATION_BINARY]` runs real assessments
against the checked-in staged lab (`test/stagedlab`) on a private, internal Docker
network and removes only the containers, network and volume it created. It never
publishes ports, attaches to production services or prunes Docker. The lab has an
approved path boundary (`/app`), an HTTPS secondary origin that is only a discovery
candidate, an unapproved alias origin, a dead port, two identities with protected
markers, valid and lookalike API definitions, GraphQL with and without
introspection, 684 distinct exact request variants, excluded logout/write routes
and a recorder that reports any request outside the boundary.

Select a suite with `STAGED_SUITE`: default (full assessment, revision and
report), `recovery`, `ui`, `identities`, `api`, `scanners`, `failures`,
`recovery-write` or `recovery-auth`. Results are native Linux arm64 with the
`xalgorix:workflow-validation-e69bc21` runtime and an application binary built
from the working tree; httpx and katana selected, `web-gentle` profile.

| Suite | What it proves | Recorded outcome |
| --- | --- | --- |
| default | plan preview and stale-fingerprint HTTP 409; job outcomes and verified artifacts; every coverage drill-down total equals its summary; all 684 variants in the inventory with a disposition; excluded write route dispositioned and never requested; alias never contacted nor counted live; stale discovery approval HTTP 409; approval creates an immutable child revision that clears write/fuzz consent; the revision runs and reaches the secondary origin; PDF totals equal API totals | 82 passed, 0 failed, 2 known limitations |
| recovery | pending approval, accepted revision and parent links survive two graceful restarts; after a SIGKILL mid-crawl the record is stopped (`server_restart`), then auto-resumed with completed httpx attempts retained under their original attempt IDs and the interrupted crawl re-run under a new attempt ID; an explicit stop is terminal across a restart and nothing is auto-resumed | all phases passed |
| ui | real Chromium against the dashboard: auth redirect and wrong-password error; the 12 coverage tiles equal the saved summary; drill-down members; exact endpoint trace; PDF download; candidate approval and revision start; the ten-minute inactivity prompt; per-tool Stop on the katana crawl; Stop all; wizard boundary, exclusions and plan fingerprint | 36 passed, 0 failed (re-run on the final commit) |
| identities | credentials stored encrypted; HTTP and browser access tests with an anonymous negative control; role separation (viewer refused the admin-only route; a public page fails the control); the assessment records authenticated observations and an independent discovery run for the additional identity; no synthetic credential, cookie or session value appears in any API response, saved artifact, output stream or the report | 34 passed, 0 failed after correcting one wrong assertion (only additional identities get their own discovery run; the primary identity uses the normal authenticated crawl) |

| api | OpenAPI and GraphQL (SDL) definitions are accepted by content hash and lookalikes, HTML prose and introspection JSON are refused; supplied path and GraphQL inputs; read-only operations tested natively; a GraphQL mutation never eligible; an exactly-once approved write reaches the lab once, its declared cleanup once, and leaves no resource; admin allowed and viewer denied a resource fixture with the marker confirmed; a GraphQL endpoint with introspection is validated and one with it disabled is recorded unavailable; no credential or fixture body in any response or the report | 45 passed, 0 failed |
| scanners | Nuclei with a signed deterministic template, Wapiti, Dalfox and a dedicated ZAP daemon in one assessment (web-thorough profile); every per-scanner drill-down total equals its summary; unproven metrics stay NOT TRACKED; Nuclei observations come only from the signed template; the approved form campaign sends exactly its cap of 12 POSTs with only the approved field names, then runs its declared cleanup and leaves no resource | 89 passed, 0 failed |
| failures | a missing binary and an unconfigured ZAP are planned unavailable with reasons and show as coverage gaps with no run; truncated Nuclei JSON and an empty Wapiti report end as PARSER_FAILED with a reason, never a clean zero-finding result; sessions expired while Nuclei runs are recorded as an authentication gap on that run, the authenticated capability is reported expired, and coverage is partial | 34 passed, 0 failed |
| recovery-write | a SIGKILL while an approved form campaign is in flight: no further POST, no replayed cleanup, every job refused with "unresolved write journal prevents automatic resume", the uncleaned resources stay visible and no run claims completion | 8 passed, 0 failed |
| recovery-auth | a SIGKILL during an authenticated crawl: the resumed assessment logs in again from the vault credentials and none of its authenticated requests carries a session token issued before the restart | 7 passed, 0 failed |

The UI suite uses `playwright-core` with the runtime image's own Chromium and a Node
binary copied from a pinned Node image, so it needs no browser download. The
scanners suite signs a throwaway Nuclei template offline
(`runtime/staged-nuclei-prepare.sh`) and runs a pinned ZAP image; the failures
suite uses the scripts in `runtime/staged-fakes`. All suites were re-run on the
final commit, in the order default (82 passed, 2 known limitations), recovery, ui,
identities, api, scanners, failures, recovery-write and recovery-auth.

### Defects found by these runs and fixed

- After a hard kill the resumed assessment parsed the truncated katana output as a
  finished crawl: the crawl was not re-run and the job ended skipped. Leftover crawl
  output is now trusted only with no earlier attempt recorded or a completed one
  with matching checksums.
- The katana crawl had no attempt ID, so the scan page offered no per-tool Stop for
  the longest preparation tool. It now registers a cancellable attempt.
- `EndpointTraceDialog` was rendered twice, hiding the first modal from assistive
  technology.
- The artifact route served `run.ArtifactPath` as soon as the tool started, although
  the file is sanitized only when the run ends. A running run, or one orphaned by a
  crash, could expose raw request/response bytes. It now returns 409 unless the run
  is terminal. Live output streams are unchanged.
- The finding status update returned an unredacted finding.
- The artifact sanitizer missed credentials embedded as JSON inside a string value.
- The recording gateway did not check resolved upstream addresses against the scope
  guard (DNS rebinding); it now resolves, checks and pins the dial.
- A browser's implicit favicon request, excluded for a path-bounded target, replaced
  the access test's failure reason and made every path-prefixed target fail the
  browser access test's anonymous negative control.
- A GraphQL operation path was joined onto a target path that already contained the
  endpoint, inventing `/app/graphql/app/graphql`: an inventory row and a probe for a
  URL that does not exist (two code paths).
- `manual_seeds` were validated and then ignored by the executor; they are now merged
  into the inventory for the first target whose scope allows them and never when
  excluded.
- An approved write that ran once with cleanup still showed as skipped on its
  operation; the apiwrites outcome is now joined onto the operation.
- A session lost mid-run while Nuclei, Wapiti or Dalfox was running left authenticated
  access reported as verified; only a ZAP failure downgraded it.

### Boundary and private-evidence audit

A static review of every adapter and of native output handling found the gaps
below. Fixed, each with a test: testssl is refused (as a policy gap) when the
approved boundary is below the origin root or excludes it; nikto checks its root URL
against the approved scope, exclusions and the scope guard; nmap refuses networks
larger than 256 addresses, asks the scope guard about the address it resolves to,
skips reverse DNS and caps its rate; an OpenVAS run that fell back to every IANA
TCP port records `network_ports_not_bounded`; new files are created owner-only
(process umask 077, inherited by scanner children); startup removes the raw artifact
of any run that never finished; the apichecks artifact is sanitized; live output is
redacted by whole line with the full sanitizer (a secret split across two reads, or
one no exact match knows, no longer reaches the saved stream, transcript or a
WebSocket client); scan deletion halts the scan first and removes only directories
inside the data directory; artifact paths are resolved through symbolic links;
uploads are created 0600; raw artifacts are withheld until their run is terminal.

Only nuclei, wapiti, dalfox and ZAP traffic passes through the recording gateway.
httpx, apichecks and the Go browser validate scope natively.
katana, testssl, nikto, nmap, masscan and OpenVAS run without the gateway; their
runs carry a `scope_not_gateway_enforced` limitation shown on the coverage job rows,
the scan detail page and the report. Remaining, accepted limitations:

- katana's headless Chromium requests `/favicon.ico` outside the approved path
  prefix (recorded by every staged run as a known limitation). Its traffic is not
  recorded as coverage events and not counted against the request budget; the same
  holds for testssl, nikto, nmap, masscan and OpenVAS.
- Header credentials, the per-attempt gateway password and the Wapiti POST body are
  passed on child command lines, so processes inside the same container can read
  them from `/proc`. The scanner runs as the container's only workload; the gateway
  password is valid only for one attempt, is scoped to the approved origins and the
  bound credential for that target, and the gateway closes when the attempt ends.
  Do not share the container's PID namespace with untrusted processes.
- The scan headers setting is shown unmasked by design (attribution identifiers);
  credentials belong in Target auth, which is masked.
- OpenVAS ignores web path, method and exclusion rules by nature; it is bounded by
  host and, when nmap evidence exists, by port.

### Not covered

Real staged runs now cover definitions, the exactly-once write, authorization
comparisons, all four active scanners, the approved campaign, injected failures and
three restart scenarios. Not covered: restart during an auth credential rotation
(only stale-session reuse after a hard kill is checked), the optional adapters
(nikto, testssl, nmap, masscan, OpenVAS), authorization comparisons for more than
two identities, authenticated ZAP execution, any run longer than the web-thorough
budget, and any amd64 run. The expanded workflow remains disabled by default.

**Platform scope.** Every result in this document is native Linux arm64 under Docker
on the operator's own machine, which is the deployment target. No amd64 run was made
and none is required for that deployment. Anyone deploying on amd64 hardware should
run the workflow below (or the same suites locally on an amd64 host) first, because
the scanner binaries and Chromium are built per architecture.

`.github/workflows/amd64-validation.yml` is a non-publishing workflow (read-only
permissions, no registry login, no push) that builds the amd64 runtime locally, runs
the smoke test, the native fixtures and a staged suite. It has not been run.

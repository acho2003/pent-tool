# Remaining Next.js execution checklist

Requested 2026-11-04: finish the practical remaining coverage and keep changes committed. The user selected **local proxy fixtures only**; no external deployment or production scan is in scope.

- [x] Extend offline dependency checks to npm v1, pnpm, and Yarn with bounded parsing, private registry redaction, and explicit ambiguous-manager coverage.
- [x] Add explicit source/deployment version evidence reconciliation without guessing target relationships.
- [x] Decode bounded supported RSC records for controlled marker comparisons; unsupported/binary/stream-error records must remain visible gaps.
- [x] Validate bounded source-map mapping segments and original-source positions while retaining privacy and partial evidence.
- [x] Exercise authenticated asset observations under the existing credential boundary; do not forward credentials to aliases/CDNs.
- [x] Add local reverse-proxy/cache acceptance and base-path/framework-version fixture coverage with measured results.
- [x] Refresh operational docs and the coverage ledger; run required checks and commit each coherent change.

Universal whole-program analysis, arbitrary action fuzzing, guessed IDs/route values, external identity-provider/MFA accounts, private-network enumeration, and unbounded fetching are outside the bounded scanner contract. Future/unrecognized protocols and formats must report unknown/partial coverage.

Verified: dependency format focused tests; source/runtime reconciliation and relationship validation tests; TypeScript and production UI build.

Verified: authenticated asset positive/negative controls and actual native Chrome delivery; browser artifact key/cookie redaction and checksum verification.

Completed 2026-11-04. Measured production compatibility: 150/150 checks (Next.js 16.4.3 root and `/tenant`, Next.js 15.5.24 root), including local reverse-proxy HTML/RSC cache isolation and verified resets. See [`baseline.compatibility.v1.json`](../../../test/nextjs-lab/baseline.compatibility.v1.json).

Final validation passed: `CGO_ENABLED=0 go test ./...`, `CGO_ENABLED=0 go vet ./...`, targeted race checks with actual Chrome authenticated asset delivery, focused protocol/dependency/reconciliation controls, Python compilation, TypeScript/production UI build, and `git diff --check`. CI is configured to repeat the compatibility matrix; it was not run remotely.

Implementation commits: `7a3c5da` (lock formats), `ec1bc5f` (explicit reconciliation and setup UI), `0ad4f13` (Flight models/mapping positions), `cd49902` (authenticated observed assets), `dc3ac5c` (closed Flight streams/partial evidence), `b116cdf` (mapping bounds), `9110a0e` (proxy/base-path/version fixtures and CI), `bcd87f3` (pinned compatibility graph and measured ledger), and `9083881` (verified partial browser findings).

No unfinished item remains in this bounded checklist. The deliberate exclusions above and the operational guide's remaining gaps still apply; this is not universal framework/protocol coverage or a production scan.

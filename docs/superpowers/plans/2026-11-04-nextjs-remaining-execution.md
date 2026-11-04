# Remaining Next.js execution checklist

Requested 2026-11-04: finish the practical remaining coverage and keep changes committed. The user selected **local proxy fixtures only**; no external deployment or production scan is in scope.

- [x] Extend offline dependency checks to npm v1, pnpm, and Yarn with bounded parsing, private registry redaction, and explicit ambiguous-manager coverage.
- [x] Add explicit source/deployment version evidence reconciliation without guessing target relationships.
- [x] Decode bounded supported RSC records for controlled marker comparisons; unsupported/binary/stream-error records must remain visible gaps.
- [x] Validate bounded source-map mapping segments and original-source positions while retaining privacy and partial evidence.
- [x] Exercise authenticated asset observations under the existing credential boundary; do not forward credentials to aliases/CDNs.
- [ ] Add local reverse-proxy/cache acceptance and base-path/framework-version fixture coverage with measured results.
- [ ] Refresh operational docs and the coverage ledger; run required checks and commit each coherent change.

Universal whole-program analysis, arbitrary action fuzzing, guessed IDs/route values, external identity-provider/MFA accounts, private-network enumeration, and unbounded fetching are outside the bounded scanner contract. Future/unrecognized protocols and formats must report unknown/partial coverage.

Verified: dependency format focused tests; source/runtime reconciliation and relationship validation tests; TypeScript and production UI build.

Verified: authenticated asset positive/negative controls and actual native Chrome delivery; browser artifact key/cookie redaction and checksum verification.

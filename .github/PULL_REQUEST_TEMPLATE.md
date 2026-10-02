<!--
Thanks for contributing to Xalgorix! Please fill this out so we can review quickly.
`main` is branch-protected — PRs are the only way in. CI runs make lint,
golangci-lint, go vet, and the test suite on every PR.
-->

## What & why

<!-- What does this change and why? Link the issue it addresses. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Docs
- [ ] Refactor / internal
- [ ] Other:

## How was it tested?

<!-- Commands you ran, new tests added, manual verification. -->

- [ ] `make lint` passes
- [ ] `golangci-lint run --config .golangci.yml ./...` passes
- [ ] `go test ./...` passes
- [ ] Added/updated tests for the change

## Checklist

- [ ] I read [CONTRIBUTING.md](../blob/main/CONTRIBUTING.md).
- [ ] The tree is `gofmt`-clean.
- [ ] I updated docs (`README`, `docs/`, help text) if behavior changed.
- [ ] This does not weaken a security control (scope guard, verifier, false-positive gate) without explicit discussion.
- [ ] For engine behavior changes: I noted any impact on scan findings/severity.

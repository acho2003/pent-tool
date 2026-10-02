# Slim runtime validation — 2026-10-02

The validated native Linux arm64 image is installed as `xalgorix:local`.
Image ID: `sha256:48e82956f7c5cde22757a9e449f023f2988686dd0dd9ae97db050f45804d5e93`.

## Measured footprint

| Measurement | Before | After |
| --- | ---: | ---: |
| Docker image-list disk usage | 29.5 GB | 5.86 GB |
| Image content size (`docker image inspect`) | 7,345,015,577 bytes | 1,073,651,780 bytes |
| Docker VM filesystem available space immediately around cleanup | 617,034,301,440 bytes | 665,552,003,072 bytes |

The image-list footprint fell approximately 80.1% (23.64 GB). Actual filesystem
space reclaimed during targeted cleanup was **48,517,701,632 bytes
(48.52 GB)**. This includes removal of temporary validation images
and the task-created dedicated builder cache, along with obsolete project images
and 471.6 MB of identifiable old project cache; it is not all attributable to the
runtime image reduction. Host APFS space recovery may lag Docker VM deletion.
Layer inspection confirms build toolchains/module caches remain in builder stages.

Largest retained component directories, measured with `du -sb`:

| Component | Bytes |
| --- | ---: |
| Prowler environment | 1,237,525,628 |
| Scout Suite environment | 806,301,318 |
| Go scanner clients (excluding relocated kube-bench binary) | 593,041,708 |
| Chromium libraries | 367,119,005 |
| Semgrep environment | 334,205,645 |
| Wapiti environment | 268,154,782 |
| Nuclei templates | 50,070,500 |

These directory sizes are uncompressed and do not sum directly to Docker's image
storage metrics. Existing ZAP/Greenbone images and feed volumes are separate and
remain retained.

## Verification completed

- All Go tests (`CGO_ENABLED=0 go test ./...`) passed, including scanner,
  assessment, attack-surface, web/authentication and application tests.
- Seven content-manifest tests passed; Compose configuration and whitespace checks passed.
- UI production build and the alternate `Dockerfile.local` Linux binary build passed.
- Offline arm64 smoke test passed all 19 scanner CLI startup checks, Python/native
  shared-library checks, Chromium headless startup, httpx/Katana link and JavaScript
  discovery, Nmap loopback probing, and Semgrep/Trivy/Gitleaks source fixtures.
  Required kube-bench configuration is present; unused tools/build executables are absent.
- Isolated dashboard accepted valid authentication and rejected unauthenticated API
  requests. All 21 integrations were registered. Existing encrypted credential
  metadata was accessible and synthetic credential CRUD passed on tmpfs data.
- A source assessment completed Gitleaks successfully and emitted verified artifacts.
  Other scanners were deliberately omitted from that custom assessment; full source
  coverage is not claimed.
- Existing ZAP API and authenticated Greenbone GMP communication passed, including
  a repeated check from the installed production container.
- App recreation preserved credential/key fingerprints, mounts, and authentication.
  No assessment was active at rollout. Only the application container was recreated.

## Build and verification limitations

The Docker VM's available memory could not compile the pinned Trivy/Vuls AWS SDK
dependency trees. Those two stripped, static Linux arm64 binaries were compiled
with host Go 1.26.5 using their exact original module pins and `GOEXPERIMENT=jsonv2`,
then supplied to a temporary build definition. Their embedded module/build metadata
was checked. All other stages used the repository Dockerfile. The committed
Dockerfile retains normal source builds for both scanners.

The existing amd64 publication workflow now builds and runs the same offline smoke
check before publishing. That remote workflow has **not been executed** in this
local session. Credentialed cloud/Kubernetes audits, vulnerability database downloads,
and a full ZAP/OpenVAS target scan were not performed. Cloud/Kubernetes planning
and public APIs were left unchanged. Burp export importing remains supported.

During rollout Docker Desktop reported a VM engine failure (`read/write on closed
pipe`). The engine was recovered without a reset. Original non-app container IDs
were preserved and their original running/stopped states were restored; their
process uptime changed during engine recovery. No original volume was removed.

## Cleanup

Removed unreferenced `xalgorix:ollama-local`, old local rollback, debug and validation
images after checking container references and other tags. Removed the dedicated
builder and its newly created cache volume. Pruned exact, verified private project
cache IDs only. Some identifiable layers remain dependency-referenced; ambiguous
shared cache was left untouched. No global Docker pruning was run. All original
56 volumes and all service/lab/other-project images were retained.

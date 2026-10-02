# Purpose-built scanner runtime

The final image uses the Debian bookworm slim multi-architecture digest recorded
in `content-lock.json`. It includes all integrated scanner clients and their
runtime dependencies, Chromium, source checkout/SSH helpers, and pinned Nuclei
templates. ZAP and Greenbone remain separate services in the default stack.
Kali metapackages, unused scanners, wordlists, and build toolchains are excluded.

Go tools are compiled and stripped in the Go builder. Python scanners use
separate virtual environments with a pinned Python 3.12 interpreter built on
Debian bookworm, matching the runtime ABI (Wapiti requires Python 3.12+).
Compilers and installation tools stay in build stages. Scanner installs fail
closed; opt-in selection does not make a bundled tool's installation optional.
Nmap, Nikto, and Lynis retain their upstream versions; masscan retains 1.3.2.
Distribution package revisions and Chromium follow Debian bookworm updates.

`content-lock.json` records scanner pins, source revisions, version commands,
and the runtime base. The build writes
`/usr/local/share/xalgorix/content-manifest.json` with the available binaries,
observed version output and provenance, and a digest/count of installed Debian
packages. Semgrep versions come from installed Python distribution metadata;
testssl versions come from its pinned installed script. Their full CLI startup
checks run in the offline smoke test, avoiding build-network-dependent probes.
Python transitive dependencies and Debian repositories are not fully archived;
this is not a claim of bit-for-bit reproducibility.

Build and verify a candidate without touching the running app:

```sh
docker build -t xalgorix:slim-candidate .
docker run --rm --network none --entrypoint python3 xalgorix:slim-candidate \
  /usr/local/share/xalgorix/smoke-test.py
python3 runtime/test_content_manifest.py
```

The offline smoke check verifies all retained clients, shared-library resolution,
Chromium headless startup, loopback httpx/Katana/Nmap discovery, local
Semgrep/Gitleaks/Trivy source analysis, and absence
of unused tools/compilers. CI runs it on amd64 before publishing. This does not
replace credentialed cloud/host audits or a full scanner quality scorecard.
The pinned ZAP daemon retains `-silent` to disable unsolicited update checks.

After candidate validation, tag it `xalgorix:local` and recreate only the app:

```sh
docker tag xalgorix:slim-candidate xalgorix:local
docker compose up -d --no-deps --no-build --pull never xalgorix
```

Keep data volumes and the credential key. Do not use `down -v` or global Docker
pruning. Remove obsolete project tags only after checking all container/image
references. Shared or unattributable builder cache should remain untouched.

`Dockerfile.local` supports application-only rebuilds from an already-built
slim image via `RUNTIME_IMAGE` (default `xalgorix:local`). It rejects historical
Kali images. Supply a Linux `build/xalgorix` matching the runtime architecture;
the normal macOS `make build` binary cannot run in Linux containers.

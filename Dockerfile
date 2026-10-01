# Xalgorix — deterministic security scanner pipeline.
#
# The runtime is based on Kali Linux and pulls in Kali's pentest metapackages,
# so hundreds of offensive-security tools are preinstalled. On top of that every
# Nuclei, Trivy, and Vuls are baked into the image. Scanner execution never
# installs software at runtime.
#
# It runs as ROOT on purpose: the engine only enables package auto-install for
# uid 0 (internal/config: AllowAutoInstall defaults to os.Getuid()==0), and
# apt/go/cargo installs need write access to system paths. The container is the
# isolation boundary — treat it as a disposable, network-isolated scanning
# sandbox and never expose the dashboard without auth.
#
# This is a large image (many GB — the full Kali toolset + wordlists + Go/Rust
# toolchains). That is intentional; size is traded for a complete toolbox.
#
# Build:  docker build -t xalgorix .
# Run:    docker run --rm -p 9137:9137 \
#           --privileged \
#           -v xalgorix-data:/data \
#           ghcr.io/xalgord/xalgorix:latest
#
# --privileged gives the toolset the same host-like access it has when run
# natively as root. Docker's DEFAULT sandbox drops capabilities (NET_ADMIN, …)
# and applies a seccomp/AppArmor filter that breaks low-level tools (iptables,
# route/interface changes, ARP-spoof/MITM, tun/tap VPNs, ptrace debuggers,
# masscan interface tuning). An image CANNOT grant itself capabilities — they
# are set at run time — so pass --privileged (or the narrower
# --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_PTRACE
# --security-opt seccomp=unconfined), or just use docker-compose.yml which
# sets privileged mode for you.
#
# Then open http://127.0.0.1:9137
#
# The source image builds for the Docker builder's target architecture, including
# Linux amd64 and arm64. Published historical releases may be amd64-only.

# ── Stage 1: build the React web UI ──────────────────────────────────────────
FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS webui
WORKDIR /src
# Copy the lockfile so npm ci installs the exact versions verified by the
# contributor (React 19 / TS 7 / Vite 8), instead of resolving fresh from
# the caret ranges on every rebuild. package-lock.json is now tracked in
# the repo (see .gitignore exception); the glob stays for any older build
# context that lacks it.
COPY webui/package.json webui/package-lock.json* ./webui/
# npm ci fails if package.json and the lockfile disagree — that is the
# point: a drift between the manifest and the lockfile must break the
# build rather than silently re-resolving to whatever is latest.
RUN cd webui && npm ci --no-audit --no-fund
COPY webui ./webui
COPY internal/web ./internal/web
RUN cd webui && npm run build

# ── Stage 2: build the Go binary + the latest Go security toolset ────────────
# Go 1.26+ is required: projectdiscovery/httpx v1.10.0 declares `go >= 1.26`, so
# a 1.25 builder can reject the pinned ProjectDiscovery httpx module.
FROM golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS gobuild
# libpcap-dev is needed to compile naabu (CGO); git for module fetches.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# ── Scanner clients FIRST, before the app source is copied ──────────────────
# These `go install`s fetch their own modules independent of the app's go.mod,
# so ordering them ahead of `COPY . .` means a code-only change never busts these
# slow tool layers — they stay cached across rebuilds. Optional legacy utilities
# remain best-effort below.
ENV GOBIN=/go/bin
# Trivy currently imports encoding/json/jsontext, which Go 1.26 exposes behind
# the jsonv2 experiment. This is compiled into the binary, not a runtime scanner
# setting.
# Cap compile parallelism (-p 4) so peak memory stays bounded: on a many-core
# Docker VM, `go install` otherwise fans out one compile/link job per CPU and
# the linker for these large dep trees (trivy: AWS SDK + k8s; vuls: similar)
# can exhaust a small Docker memory allotment and get OOM-killed, surfacing as
# a bare "exit code: 1" with no Go error. Separate RUN layers also mean a
# failure names the exact tool and successful tools stay cached on rebuild.
RUN go install -v -p 4 github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
RUN GOEXPERIMENT=jsonv2 go install -v -p 4 github.com/aquasecurity/trivy/cmd/trivy@v0.74.0
RUN GOEXPERIMENT=jsonv2 go install -v -p 4 github.com/future-architect/vuls/cmd/vuls@v0.41.0
RUN go install -v -p 4 github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
RUN go install -v -p 4 github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0
RUN go install -v -p 4 github.com/projectdiscovery/katana/cmd/katana@v1.7.0
RUN go install -v -p 4 github.com/zricethezav/gitleaks/v8@v8.30.1
# Pinned to osv-scanner v1: buildOSV uses the v1 CLI form (bare invocation with
# --format/--output/-r). v2 restructured the CLI into `scan source`; installing
# v2 here would make the bare invocation exit non-zero and its findings would be
# recorded as a failed run. v1 still queries the live OSV.dev database, so vuln
# coverage is current regardless of binary version.
RUN go install -v -p 4 github.com/google/osv-scanner/cmd/osv-scanner@v1.9.2

RUN set -eux; \
    for pkg in \
      github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1 \
      github.com/jaeles-project/gospider@v1.1.6 \
      github.com/lc/gau/v2/cmd/gau@v2.2.4 \
      github.com/tomnomnom/waybackurls@v0.1.0 \
      github.com/tomnomnom/assetfinder@v0.1.1 \
      github.com/tomnomnom/qsreplace@v0.0.3 \
      github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5 \
      github.com/tomnomnom/anew@v0.1.1 \
      github.com/hakluke/hakrawler@v0.0.0-20260805040537-52a16fe61bd1 \
      github.com/OJ/gobuster/v3@v3.8.2 \
      github.com/ffuf/ffuf/v2@v2.3.0 \
      github.com/hahwul/dalfox/v2@v2.13.0 \
      github.com/projectdiscovery/mapcidr/cmd/mapcidr@v1.1.97 \
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@v1.4.1 \
      github.com/projectdiscovery/notify/cmd/notify@v1.0.7 \
      github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1 \
      github.com/tomnomnom/unfurl@v0.4.3 \
      github.com/tomnomnom/gron@v0.7.1 \
      github.com/tomnomnom/httprobe@v0.1.2 \
      github.com/haccer/subjack@v0.0.0-20260316055456-b53899ce6230 \
      github.com/securego/gosec/v2/cmd/gosec@v2.29.0 \
      github.com/aquasecurity/kube-bench@v0.16.0 \
    ; do go install -v "$pkg" || echo "WARN: optional utility $pkg unavailable"; done; \
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 \
      || echo "WARN: optional naabu utility unavailable"

# ── App build LAST — only this and below re-run on a code change ─────────────
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=webui /src/internal/web/static ./internal/web/static
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/xalgorix ./cmd/xalgorix/

# ── Stage 3: runtime — Kali Linux, full toolset, runs as root ────────────────
FROM kalilinux/kali-last-release@sha256:61d2b988d3be6b5b2d8f55b40946a2b82f98e71f961927a4c44ba70b0ec95542

ENV DEBIAN_FRONTEND=noninteractive

# Kali metapackages = the extensive toolset. Recommends are left ON so the
# metapackages pull their full tool set. Use Kali's direct signed-repository
# endpoint: the HTTP mirror redirector can select unreachable regional mirrors
# during ARM image builds. Package managers remain available for operators,
# while scanner runtime auto-install is disabled.
RUN sed -i -e 's|http://http.kali.org/kali|https://kali.download/kali|g' \
           -e 's|kali-rolling|kali-last-snapshot|g' /etc/apt/sources.list.d/kali.sources \
    && apt-get update \
    && set -- /var/lib/apt/lists/*kali-last-snapshot_InRelease \
    && test -f "$1" \
    && echo "5bc9a9bf729d7f9a0c360afe66488379a04d809cbaa7ad4fcefe1704266f5f51  $1" | sha256sum -c - \
    && apt-get install -y \
      kali-linux-headless \
      kali-tools-information-gathering \
      kali-tools-web \
      kali-tools-vulnerability \
      kali-tools-fuzzing \
      kali-tools-passwords \
      kali-tools-exploitation \
      kali-tools-post-exploitation \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip zip p7zip-full file tree bc xxd \
      seclists wordlists \
      python3 python3-pip python3-venv pipx \
      cargo \
      nodejs npm \
      build-essential pkg-config libpcap-dev libcap2-bin \
      chromium \
      findomain dirsearch \
    && rm -rf /var/lib/apt/lists/*

# Strip file capabilities from every bundled tool so a plain `docker run` works.
#
# Kali ships several tools (nmap most notably, at /usr/lib/nmap/nmap) with file
# capabilities set with the EFFECTIVE bit, e.g. cap_net_raw,cap_net_admin,
# cap_net_bind_service+eip. Under Docker's DEFAULT security profile the
# capability bounding set drops NET_ADMIN, and the kernel fails execve() with
# EPERM ("Operation not permitted") whenever a binary requests an effective
# capability that isn't in the bounding set — so `nmap` won't even start under a
# default `docker run`, with no cap-add/seccomp overrides.
#
# The engine runs as ROOT on purpose, and root already holds NET_RAW in Docker's
# default bounding set, so these file caps are redundant: removing them lets the
# binaries exec cleanly and fall back to root's own capabilities for raw-socket
# scans. This clears the entire class of "Operation not permitted" exec errors
# (nmap, masscan, arping, dumpcap, …) for containerized deployments.
RUN getcap -r / 2>/dev/null | awk '{print $1}' | while read -r f; do \
      setcap -r "$f" 2>/dev/null || true; \
    done || true

# Go toolchain at runtime so the runtime can `go install` anything not baked in.
COPY --from=gobuild /usr/local/go /usr/local/go
# Prebuilt pinned Go security tools → on PATH via /root/go/bin. This comes from
# the gobuild stage's cached tool layers, so it stays cached across code changes.
# The xalgorix binary itself is copied LAST (near ENTRYPOINT) so a code-only
# rebuild busts only that final layer, not the tool installs below.
COPY --from=gobuild /go/bin/ /root/go/bin/

ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:/root/.local/bin:${PATH}" \
    GOBIN=/root/go/bin \
    HOME=/root

# feroxbuster (Rust) — Kali packages it, but grab the latest release binary too
# so it's current; cargo stays available at runtime as the engine's fallback.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) ferox_arch=x86_64; ferox_sha=0978619a10049ccaad290b2d1241bc4d8a6aac18da07d6231186fb9d343f99de ;; \
      arm64) ferox_arch=aarch64; ferox_sha=1e5244e1f52e55a647b65e0c76ae7afe0b9983c1fbea30ed7c67e477175eb381 ;; \
      *) echo "WARN: feroxbuster is unavailable for $TARGETARCH"; exit 0 ;; \
    esac; \
    curl -fsSLo /tmp/ferox.zip "https://github.com/epi052/feroxbuster/releases/download/v2.13.1/${ferox_arch}-linux-feroxbuster.zip" \
    && echo "$ferox_sha  /tmp/ferox.zip" | sha256sum -c - \
    && unzip -o /tmp/ferox.zip -d /usr/local/bin feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm -f /tmp/ferox.zip \
    || echo "WARN: feroxbuster prefetch failed (present via Kali/cargo)"

# Python tools installed at image build time. gvm-tools is kept for interactive
# operator use only — the scanner pipeline speaks GMP natively (internal/scanner
# /gmp.go) because gvm-tools refuses to run under uid 0, and this image runs as
# root by design. Each tool is installed on its own so a single flaky package
# never fails the image; the rest stay runtime-installable via the
# packageMap → pipx path.
RUN pipx install 'gvm-tools==26.1.1' || pip3 install --break-system-packages 'gvm-tools==26.1.1'
RUN pipx install 'semgrep==1.178.0'
RUN for p in 'scrapling==0.4.15' 'bandit==1.9.4' 'git-dumper==1.0.9' 'arjun==2.2.7' 'uro==1.0.2'; do \
      pipx install "$p" || pip3 install --break-system-packages "$p" \
        || echo "WARN: pipx prefetch of $p failed (installable at runtime)"; \
    done

# Staged web-pipeline scanner (Python): wapiti3 provides the `wapiti` binary.
# Best-effort per tool so a flaky package never fails the image.
RUN for p in 'wapiti3==3.3.2'; do \
      pipx install "$p" || pip3 install --break-system-packages "$p" \
        || echo "WARN: pipx prefetch of $p failed (installable at runtime)"; \
    done

# Cloud posture-audit scanners (Python): prowler (AWS audit) and scoutsuite
# (provides the `scout` binary). Read-only; they need a supplied credential at
# scan time (never baked into the image). kube-bench (CIS Kubernetes) is a Go
# binary installed above; it needs cluster/node access provided by the operator.
RUN for p in 'prowler==5.44.0' 'scoutsuite==5.14.0'; do \
      pipx install "$p" || pip3 install --break-system-packages "$p" \
        || echo "WARN: pipx prefetch of $p failed (installable at runtime)"; \
    done

# paramspider — the real tool is GitHub-only (PyPI `paramspider` is an empty
# 1.3 kB stub with no CLI), so install straight from the repo.
RUN pipx install "git+https://github.com/devanshbatham/paramspider.git@c44bdaae54789b237028e309b603d1aa5ad52e5e" \
    || echo "WARN: paramspider prefetch failed (installable at runtime)"

# Ruby (Rails SAST) — best-effort.
RUN gem install --no-document brakeman -v 8.1.0 || echo "WARN: brakeman prefetch failed"

# trufflehog — no clean `go install` (its go.mod uses replace directives), so
# pull the official release binary into /usr/local/bin.
RUN case "$TARGETARCH" in \
      amd64) truffle_sha=40377e6572495412fb9ba0bc21c9401f73b72f1d2afd11b9931bc4a5ed622866 ;; \
      arm64) truffle_sha=372c568695d49e53517075b5f74d1ee9a19053f13661d689c7928ee1fc27d705 ;; \
      *) echo "WARN: trufflehog is unavailable for $TARGETARCH"; exit 0 ;; \
    esac; \
    curl -fsSLo /tmp/trufflehog.tar.gz "https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.9/trufflehog_3.97.9_linux_${TARGETARCH}.tar.gz" \
    && echo "$truffle_sha  /tmp/trufflehog.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog \
    && rm /tmp/trufflehog.tar.gz \
    || echo "WARN: trufflehog prefetch failed"

# CMSmap — git-cloned CMS scanner; expose a `cmsmap` wrapper on PATH.
RUN git init /opt/CMSmap \
    && git -C /opt/CMSmap fetch --depth 1 https://github.com/Dionach/CMSmap.git 59dd0e2b3b0c751c6da2b0565374ab83c736b0e6 \
    && git -C /opt/CMSmap checkout --detach FETCH_HEAD \
    && (pip3 install --break-system-packages -r /opt/CMSmap/requirements.txt 2>/dev/null || true) \
    && printf '#!/bin/sh\nexec python3 /opt/CMSmap/cmsmap.py "$@"\n' > /usr/local/bin/cmsmap \
    && chmod +x /usr/local/bin/cmsmap \
    || echo "WARN: cmsmap prefetch failed (installable at runtime)"

# testssl.sh — TLS/cert scanner (bash script; needs its bundled etc/ data dir)
RUN git init /opt/testssl.sh \
      && git -C /opt/testssl.sh fetch --depth 1 https://github.com/testssl/testssl.sh.git 5b900792f2a6a86135d1151e965c05c59a861e72 \
      && git -C /opt/testssl.sh checkout --detach FETCH_HEAD \
      && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Bake nuclei templates so first-run scans don't stall on a template fetch.
RUN git init /opt/nuclei-templates \
    && git -C /opt/nuclei-templates fetch --depth 1 https://github.com/projectdiscovery/nuclei-templates.git 8b9d065ccb0492d39f7680c908b3030a97ddfe1b \
    && git -C /opt/nuclei-templates checkout --detach FETCH_HEAD

COPY runtime/content-lock.json /usr/local/share/xalgorix/content-lock.json
COPY runtime/write-content-manifest.py /usr/local/bin/write-content-manifest.py
RUN python3 /usr/local/bin/write-content-manifest.py /usr/local/share/xalgorix/content-lock.json \
      /usr/local/share/xalgorix/content-manifest.json

# Make `httpx` resolve to ProjectDiscovery's scanner. Kali/pip ship a Python
# `httpx` CLI (the HTTP client) at /usr/bin/httpx that otherwise answers `httpx`
# and breaks the engine's recon (unknown flags like -silent/-title). /root/go/bin
# is already ahead of /usr/bin on PATH; also point the absolute path at the PD
# binary so nothing falls back to the Python client.
RUN if [ -x /root/go/bin/httpx ]; then ln -sf /root/go/bin/httpx /usr/bin/httpx; \
    else echo "WARN: ProjectDiscovery httpx not baked into /root/go/bin"; fi

ENV XALGORIX_BIND=0.0.0.0 \
    XALGORIX_BROWSER_PATH=/usr/bin/chromium \
    XALGORIX_NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    XALGORIX_DATA_DIR=/data \
	XALGORIX_ALLOW_AUTO_INSTALL=0 \
    XALGORIX_NO_AUTO_UPDATE=1

# Entrypoint generates dashboard credentials when none are supplied (the image
# binds 0.0.0.0, which the engine won't do without auth) so a plain
# `docker run` starts cleanly and securely.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 9137

# The xalgorix binary is copied LAST so a code-only change re-runs only this
# tiny layer (plus the metadata below) and reuses every cached tool layer above.
COPY --from=gobuild /out/xalgorix /usr/local/bin/xalgorix

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--web"]

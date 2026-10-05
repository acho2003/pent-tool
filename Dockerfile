# syntax=docker/dockerfile:1
# Purpose-built runtime. ZAP and Greenbone run as separate Compose services.
# Build tooling and unused pentest packages never enter the final image.

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
RUN cd webui && npm ci --include=optional --no-audit --no-fund
COPY webui ./webui
COPY internal/web ./internal/web
RUN cd webui && npm run build

# ── Stage 2: build the Go binary + pinned scanner clients ────────────
# Go 1.26+ is required: projectdiscovery/httpx v1.10.0 declares `go >= 1.26`, so
# a 1.25 builder can reject the pinned ProjectDiscovery httpx module.
FROM golang:1.26-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS gobuild
# Scanner modules are fetched only in the builder.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# ── Scanner clients FIRST, before the app source is copied ──────────────────
# These `go install`s fetch their own modules independent of the app's go.mod,
# so ordering them ahead of `COPY . .` means a code-only change never busts these
# slow tool layers — they stay cached across rebuilds.
ENV GOBIN=/go/bin CGO_ENABLED=0 GOMEMLIMIT=768MiB GOGC=20 GOMAXPROCS=2
# Trivy currently imports encoding/json/jsontext, which Go 1.26 exposes behind
# the jsonv2 experiment. This is compiled into the binary, not a runtime scanner
# setting.
# Cap compile parallelism (-p 1) and Go heap growth so memory stays bounded: on a many-core
# Docker VM, `go install` otherwise fans out one compile/link job per CPU and
# the linker for these large dep trees (trivy: AWS SDK + k8s; vuls: similar)
# can exhaust a small Docker memory allotment and get OOM-killed, surfacing as
# a bare "exit code: 1" with no Go error. Separate RUN layers also mean a
# failure names the exact tool and successful tools stay cached on rebuild.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build GOEXPERIMENT=jsonv2 go install -v -p 1 -ldflags="-s -w" github.com/aquasecurity/trivy/cmd/trivy@v0.74.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build GOEXPERIMENT=jsonv2 go install -v -p 1 -ldflags="-s -w" github.com/future-architect/vuls/cmd/vuls@v0.41.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/owasp-amass/amass/v4/cmd/amass@v4.2.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/lc/gau/v2/cmd/gau@v2.2.4
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/tomnomnom/waybackurls@v0.1.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@v1.7.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/zricethezav/gitleaks/v8@v8.30.1
# Pinned to osv-scanner v1: buildOSV uses the v1 CLI form (bare invocation with
# --format/--output/-r). v2 restructured the CLI into `scan source`; installing
# v2 here would make the bare invocation exit non-zero and its findings would be
# recorded as a failed run. v1 still queries the live OSV.dev database, so vuln
# coverage is current regardless of binary version.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/google/osv-scanner/cmd/osv-scanner@v1.9.2

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/hahwul/dalfox/v2@v2.13.0
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go install -v -p 1 -ldflags="-s -w" github.com/aquasecurity/kube-bench@v0.16.0 \
    && mkdir -p /out/kube-bench \
    && cp -R /go/pkg/mod/github.com/aquasecurity/kube-bench@v0.16.0/cfg /out/kube-bench/ \
    && cp /go/pkg/mod/github.com/aquasecurity/kube-bench@v0.16.0/helper_scripts/check_files_owner_in_dir.sh /go/bin/

# ── App build LAST — only this and below re-run on a code change ─────────────
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
COPY . .
COPY --from=webui /src/internal/web/static ./internal/web/static
ARG VERSION=docker
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/xalgorix ./cmd/xalgorix/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/go-buildinfo ./runtime/go-buildinfo.go

# Pinned Debian runtime; Python scanner environments use the same Debian ABI.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS debian-base

# Python installation tools and native compilers stay in this stage.
FROM python:3.12-slim-bookworm@sha256:bc01d00b6417e4b1b01c331db3a14054b4be954e571ef8bf5748aaf64b66e941 AS python-build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libffi-dev libssl-dev \
      libxml2-dev libxslt1-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Isolated environments preserve scanner dependency compatibility without pip
# or setuptools being bootstrapped into each runtime environment.
RUN python3 -m venv --without-pip /opt/venvs/semgrep \
    && python3 -m pip --python /opt/venvs/semgrep install --no-compile 'semgrep==1.178.0'
RUN python3 -m venv --without-pip /opt/venvs/wapiti \
    && python3 -m pip --python /opt/venvs/wapiti install --no-compile 'wapiti3==3.3.2'
RUN python3 -m venv --without-pip /opt/venvs/prowler \
    && python3 -m pip --python /opt/venvs/prowler install --no-compile 'prowler==5.44.0'
RUN python3 -m venv --without-pip /opt/venvs/scoutsuite \
    && python3 -m pip --python /opt/venvs/scoutsuite install --no-compile 'scoutsuite==5.14.0'
RUN python3 -m venv --without-pip /opt/venvs/sslyze \
    && python3 -m pip --python /opt/venvs/sslyze install --no-compile 'sslyze==6.3.1'
# Export only the interpreter/stdlib and scanner environments, not installers.
RUN python3 -m pip uninstall -y pip setuptools wheel \
    && rm -rf /usr/local/include /usr/local/lib/pkgconfig /usr/local/share/man


# Preserve the installed upstream tool versions without the Kali toolbox.
FROM debian-base AS native-build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates bzip2 libssl-dev libssh2-1-dev \
      libpcap-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/nmap
RUN curl -fsSL https://nmap.org/dist/nmap-7.99.tar.bz2 -o nmap.tar.bz2 \
    && echo 'df512492ffd108e53a27a06f26d8635bbe89e0e569455dc8ffef058c035d51b2  nmap.tar.bz2' | sha256sum -c - \
    && tar -xjf nmap.tar.bz2 --strip-components=1 \
    && ./configure --prefix=/usr --without-zenmap --without-ndiff --without-ncat --without-nping \
    && make -j4 && make DESTDIR=/out install \
    && strip /out/usr/bin/nmap

FROM debian-base AS content-build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git init /opt/nikto \
    && git -C /opt/nikto fetch --depth 1 https://github.com/sullo/nikto.git 69681e2e4213c15b85a90c53b2169ecb2a88fb01 \
    && git -C /opt/nikto checkout --detach FETCH_HEAD \
    && rm -rf /opt/nikto/.git
RUN git init /opt/lynis \
    && git -C /opt/lynis fetch --depth 1 https://github.com/CISOfy/lynis.git 06153321ea50d53a27446084e646d9f43fe46e0e \
    && git -C /opt/lynis checkout --detach FETCH_HEAD \
    && rm -rf /opt/lynis/.git
RUN git init /opt/testssl.sh \
    && git -C /opt/testssl.sh fetch --depth 1 https://github.com/testssl/testssl.sh.git 5b900792f2a6a86135d1151e965c05c59a861e72 \
    && git -C /opt/testssl.sh checkout --detach FETCH_HEAD \
    && rm -rf /opt/testssl.sh/.git
RUN git init /opt/nuclei-templates \
    && git -C /opt/nuclei-templates fetch --depth 1 https://github.com/projectdiscovery/nuclei-templates.git 8b9d065ccb0492d39f7680c908b3030a97ddfe1b \
    && git -C /opt/nuclei-templates checkout --detach FETCH_HEAD \
    && rm -rf /opt/nuclei-templates/.git

FROM debian-base AS runtime
ARG VCS_REF=unknown
LABEL org.opencontainers.image.revision=${VCS_REF}
ENV DEBIAN_FRONTEND=noninteractive
# Runtime libraries, browser, and helpers required by the retained scanners.
# masscan retains upstream 1.3.2; other native scanners are copied from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git openssh-client openssl python3 chromium \
      masscan perl libnet-ssleay-perl libio-socket-ssl-perl \
      libpcap0.8 libssh2-1 libpcre2-8-0 libxml2 libxslt1.1 libffi8 libgomp1 \
      libgmp10 libmagic1 dnsutils procps bsdextrautils file xxd jq \
    && rm -rf /var/lib/apt/lists/*
# Nikto requires these Perl modules even for startup/version checks.
RUN apt-get update && apt-get install -y --no-install-recommends libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=native-build /out/usr/bin/nmap /usr/bin/nmap
COPY --from=native-build /out/usr/share/nmap /usr/share/nmap
COPY --from=gobuild /go/bin/ /root/go/bin/
COPY --from=gobuild /out/kube-bench/ /opt/kube-bench/
COPY --from=python-build /usr/local/ /usr/local/
COPY --from=python-build /opt/venvs/ /opt/venvs/
COPY --from=content-build /opt/ /opt/
ENV PATH="/root/go/bin:${PATH}" HOME=/root \
    PYTHONDONTWRITEBYTECODE=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
RUN ldconfig \
    && mv /root/go/bin/kube-bench /opt/kube-bench/kube-bench \
    && printf '#!/bin/sh\ncd /opt/kube-bench\nexec ./kube-bench "$@"\n' > /root/go/bin/kube-bench \
    && chmod +x /root/go/bin/kube-bench /root/go/bin/check_files_owner_in_dir.sh \
    && ln -s /opt/venvs/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && ln -s /opt/venvs/wapiti/bin/wapiti /usr/local/bin/wapiti \
    && ln -s /opt/venvs/prowler/bin/prowler /usr/local/bin/prowler \
    && ln -s /opt/venvs/scoutsuite/bin/scout /usr/local/bin/scout \
    && ln -s /opt/venvs/sslyze/bin/sslyze /usr/local/bin/sslyze \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && printf '#!/bin/sh\ncd /opt/lynis\nexec ./lynis "$@"\n' > /usr/bin/lynis \
    && chmod +x /usr/bin/lynis \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/bin/nikto \
    && chmod +x /usr/bin/nikto \
    && ln -s /root/go/bin/httpx /usr/bin/httpx
COPY runtime/content-lock.json /usr/local/share/xalgorix/content-lock.json
COPY runtime/write-content-manifest.py /usr/local/bin/write-content-manifest.py
COPY runtime/smoke-test.py /usr/local/share/xalgorix/smoke-test.py
COPY --from=gobuild /out/go-buildinfo /usr/local/bin/go-buildinfo
RUN --network=none python3 /usr/local/bin/write-content-manifest.py /usr/local/share/xalgorix/content-lock.json \
      /usr/local/share/xalgorix/content-manifest.json
ENV XALGORIX_BIND=0.0.0.0 \
    XALGORIX_BROWSER_PATH=/usr/bin/chromium \
    XALGORIX_NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    XALGORIX_DATA_DIR=/data \
    XALGORIX_ALLOW_AUTO_INSTALL=0 \
    XALGORIX_NO_AUTO_UPDATE=1
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data
VOLUME ["/data"]
EXPOSE 9137
COPY --from=gobuild /out/xalgorix /usr/local/bin/xalgorix
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--web"]

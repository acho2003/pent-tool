# Xalgorix runtime tools

The Debian slim image contains the integrated scanner clients and their runtime
dependencies. It does not bundle the general Kali toolbox. Installed scanners
are not necessarily selected for every assessment: target capabilities,
credentials, service configuration, and explicit selection still apply.

## Integrated scanner registry (by group)

These are the scanners the deterministic pipeline / assessment planner drives
directly, organized into the groups shown in **New Assessment**. Each has a
scoped adapter, tolerant result parsing, and explicit coverage/failure states.
Optional scanners are off unless selected; availability reflects whether the
tool binary (and any required credential) is present.

| Group | Scanners |
c

`*` = optional / opt-in.

### Cloud & Kubernetes audit scanners (new)

All three are **read-only** posture/compliance audits. Credentials are supplied
per scan, passed to the tool via environment only (never argv), redacted from
output, and never stored in scan records, logs, artifacts, or reports.

| Scanner | Audits | Target | Operator setup |
|---|---|---|---|
| **prowler** | AWS security & configuration | Cloud account | Store a **read-only** AWS credential in the vault bound to the cloud target (env vars, e.g. `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, plus `provider=aws`). |
| **scoutsuite** | AWS / GCP / Azure posture | Cloud account | Store a **read-only** cloud credential in the vault bound to the target; set `provider` to `aws`/`gcp`/`azure`. |
| **kube-bench** | CIS Kubernetes benchmark | Kubernetes cluster | kube-bench is node-local: run Xalgorix where it can inspect the cluster (on a node) or deploy kube-bench in-cluster. |

Tool paths are overridable via `XALGORIX_PROWLER_PATH`, `XALGORIX_SCOUTSUITE_PATH`,
and `XALGORIX_KUBEBENCH_PATH`.

## Runtime helpers and services

Chromium supports Katana's browser crawl. Git clones source repositories; SSH
supports host audits. Bash, OpenSSL, Perl, DNS helpers, Python, and shared
libraries support scanner execution. Nuclei templates are pinned scan content.

ZAP and Greenbone/OpenVAS run in the existing separate Compose services. Their
images, feeds, and databases are retained. Xalgorix communicates with Greenbone
using native GMP; standalone gvm-tools is not installed in the app image.

Burp Suite XML exports can still be imported, but Burp binaries are not bundled.
Caido and Wazuh integrations remain available for externally managed services;
Caido is not bundled in the image.

## Removed toolbox packages

The runtime no longer includes broad Kali metapackages, SecLists/wordlists,
Burp Suite, CMSmap, feroxbuster, trufflehog, bandit, brakeman, gosec, scrapling,
paramspider, git-dumper, arjun, uro, or the unrelated Go reconnaissance/fuzzing
utilities formerly installed by the Dockerfile. Go, Cargo/Rust, Node/npm, C/C++
compilers, and Python installation tools remain confined to build stages.

The machine-readable inventory is `/usr/local/share/xalgorix/content-manifest.json`.
See [runtime validation](runtime/README.md) for build and smoke-check commands.

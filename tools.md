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
|---|---|
| Web / API | Native API checks, Nuclei, OWASP ZAP, Nikto*, Wapiti*, Dalfox* |
| Network / discovery | Subfinder*, Amass*, DNSX, HTTPX, Katana, Nmap, Masscan* |
| Historical URL discovery | gau*, waybackurls* (select one provider) |
| TLS | testssl.sh, SSLyze* |
| Source / dependency | Semgrep, Gitleaks, OSV-Scanner, Trivy |
| Host / infrastructure | Vuls, Lynis, Greenbone/OpenVAS |
| Cloud / Kubernetes | Prowler*, Scout Suite*, kube-bench* |

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
| **kube-exposure** | URL-only Kubernetes exposure checks | Explicit HTTP(S) URL | Optional native read-only checks for externally visible management surfaces; does not inspect cluster configuration. |
| **nextjs-assets** | Next.js fingerprint, known advisories, public source maps and build-manifest routes | HTTP(S) URL, domain or host | Optional native read-only checks of served JavaScript; anonymous GETs to in-scope URLs only; source-map content is not retained. |

Tool paths are overridable via `XALGORIX_PROWLER_PATH`, `XALGORIX_SCOUTSUITE_PATH`,
and `XALGORIX_KUBEBENCH_PATH`.

### Threat intelligence lookups (optional, API-key gated)

These ask a third-party service about the target's public IP, domain or locked
npm dependencies. They never send a request to the target, but the target
identifier is disclosed to the provider. All are opt-in per assessment and stay
unavailable until their key is set under **Settings → Intelligence API keys**
(no restart needed).

| Scanner | Key(s) | Reports |
|---|---|---|
| `intel-shodan` | `SHODAN_API_KEY` | Internet-visible services and banner-matched CVEs |
| `intel-censys` | `CENSYS_API_TOKEN` (`CENSYS_ORG_ID` optional) | Internet-visible services |
| `intel-shadowserver` | `SHADOWSERVER_API_KEY`, `SHADOWSERVER_API_SECRET` | Shadowserver report events for the IP |
| `intel-greynoise` | `GREYNOISE_API_KEY` | Target IP seen scanning/attacking the internet |
| `intel-abuseipdb` | `ABUSEIPDB_API_KEY` | Abuse reports against the IP |
| `intel-crtsh` | none | Hostnames in certificate-transparency logs (candidates only) |
| `intel-hibp` | `HIBP_API_KEY` | Breached accounts on the verified domain (counts only) |
| `intel-github-leaks` | `GITHUB_TOKEN` | Public code mentioning the domain with credential keywords |
| `intel-dehashed` | `DEHASHED_API_KEY` | Count of leaked credential records |
| `intel-cloudflare` | `CLOUDFLARE_API_TOKEN` (read-only) | Weak zone TLS settings, DNS records that bypass the proxy |
| `intel-socket` | `SOCKET_API_TOKEN` | Malicious or risky npm packages (needs `package-lock.json`) |
| `intel-depsdev` | none | Deprecated or low-Scorecard direct npm dependencies |

`SECURITYTRAILS_API_KEY`, `CHAOS_API_KEY`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`
and `GITHUB_TOKEN` are also passed to Subfinder as extra passive sources;
`VIRUSTOTAL_API_KEY` is passed to waybackurls. The provider response parsers are
covered by stubbed tests only and have not been run against the live services.

## Runtime helpers and services

Chromium supports Katana's browser crawl. Git clones source repositories; SSH
supports host audits. Bash, OpenSSL, Perl, DNS helpers, Python, and shared
libraries support scanner execution. Nuclei templates are pinned scan content.
DNSX, Amass, gau, waybackurls, and SSLyze are included for the typed web/API
workflow; passive discovery providers remain opt-in and never add scan scope.

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

# Xalgorix Tools

Complete list of the security tools included in Xalgorix - a deterministic, open-source security-scanner pipeline.

## 🔍 Recon & Subdomain Enumeration (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **subfinder** | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| 2 | **findomain** | Subdomain discovery | `cargo install findomain` |
| 3 | **assetfinder** | Find related subdomains | `go install github.com/tomnomnom/assetfinder@latest` |
| 4 | **dnsx** | DNS resolution & bruteforce | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| 5 | **amass** | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@latest` |
| 6 | **gospider** | Web spidering | `go install github.com/jaeles-project/gospider@latest` |
| 7 | **katana** | Next-gen crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| 8 | **hakrawler** | Web crawling | `go install github.com/hakluke/hakrawler@latest` |
| 9 | **gau** | Get All URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| 10 | **waybackurls** | Wayback Machine URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| 11 | **paramspider** | Parameter discovery | `pipx install paramspider` |
| 12 | **crt.sh** | Certificate transparency | `curl -s "https://crt.sh/?q=target.com"` |
| 13 | **bufferover** | DNS enumeration | `curl -s "https://dns.bufferover.run/dns?q=target.com"` |
| 14 | **webarchive** | Historical URLs | `curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*"` |
| 15 | **shuffledns** | DNS bruteforce | `go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |

## 🌐 HTTP & Scanning (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| 2 | **nuclei** | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| 3 | **gobuster** | Directory busting | `go install github.com/OJ/gobuster/v3@latest` |
| 4 | **ffuf** | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| 5 | **feroxbuster** | Recursive fuzzing | `cargo install feroxbuster --locked` |
| 6 | **dirsearch** | Web path scanning | `git clone https://github.com/maurosoria/dirsearch` |
| 7 | **dirb** | Web scanning | `apt install dirb` |
| 8 | **nikto** | Web server scanning | `apt install nikto` |
| 9 | **wfuzz** | Web fuzzing | `pip install wfuzz` |
| 10 | **whatweb** | Web technology fingerprint | `apt install whatweb` |
| 11 | **wappalyzer** | Technology stack detection | `npm install -g wappalyzer` |
| 12 | **builtwith** | Technology lookup | `pip install builtwith` |
| 13 | **wpscan** | WordPress scanner | `gem install wpscan` |
| 14 | **joomscan** | Joomla scanner | `git clone https://github.com/rezasp/joomscan` |
| 15 | **cmsmap** | CMS scanner | `git clone https://github.com/Dionach/CMSmap` |

## 💉 Exploitation (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **sqlmap** | SQL injection | `git clone https://github.com/sqlmapproject/sqlmap` |
| 2 | **nmap** | Port & service scanning | `apt install nmap` |
| 3 | **masscan** | Fast port scanner | `apt install masscan` |
| 4 | **naabu** | Fast port scanner | `go install github.com/projectdiscovery/naabu/cmd/naabu@latest` |
| 5 | **arp-scan** | ARP discovery | `apt install arp-scan` |
| 6 | **netdiscover** | Network discovery | `apt install netdiscover` |
| 7 | **responder** | LLMNR/NBTNS spoofing | `git clone https://github.com/SpiderLabs/Responder` |
| 8 | **impacket** | Windows exploitation | `pip install impacket` |
| 9 | **secretdump** | SAM database dump | `pip install impacket` |
| 10 | **evilwinrm** | Windows remoting | `gem install evilwinrm` |
| 11 | **hydra** | Password cracking | `apt install hydra` |
| 12 | **medusa** | Password cracking | `apt install medusa` |
| 13 | **john** | Password cracking | `apt install john` |
| 14 | **hashcat** | GPU password cracking | `apt install hashcat` |
| 15 | **crackmapexec** | Network exploitation | `pip install crackmapexec` |

## 🕵️ Information Gathering (10 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **theHarvester** | Email gathering | `git clone https://github.com/laramies/theHarvester` |
| 2 | **metagoofil** | Metadata extraction | `pip install metagoofil` |
| 3 | **spiderfoot** | OSINT automation | `pip install spiderfoot` |
| 4 | **recon-ng** | Web reconnaissance | `pip install recon-ng` |
| 5 | **maltego** | Graphical OSINT | `apt install maltego` |
| 6 | **gh** | GitHub reconnaissance | `apt install gh` |
| 7 | **git-dumper** | Git repository dump | `pip install git-dumper` |
| 8 | **gittools** | Git exploitation | `git clone https://github.com/internetwache/GitTools` |
| 9 | **trufflehog** | Secret scanning | `go install github.com/trufflesecurity/trufflehog@latest` |
| 10 | **gitleaks** | Secret detection | `go install github.com/gitleaks/gitleaks@latest` |

## 🔐 Security Scanning (10 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **zaproxy** | Web app scanner | `apt install zaproxy` |
| 2 | **burpsuite** | Web vulnerability | `apt install burpsuite` |
| 3 | **semgrep** | Static analysis | `pip install semgrep` |
| 4 | **bandit** | Python security | `pip install bandit` |
| 5 | **brakeman** | Ruby on Rails security | `gem install brakeman` |
| 6 | **gosec** | Go security | `go install github.com/securego/gosec@latest` |
| 7 | **sonarqube** | Code quality | `docker run -d --name sonarqube -p 9000:9000 sonarqube` |
| 8 | **owasp-zap** | App security | `apt install zaproxy` |
| 9 | **mitmproxy** | HTTP proxy | `apt install mitmproxy` |
| 10 | **sslyze** | TLS analysis | `pip install sslyze` |

## 🛡️ WAF & Protection (5 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **wafw00f** | WAF detection | `pip install wafw00f` |
| 2 | **whatwaf** | WAF identification | `pip install whatwaf` |
| 3 | **bountycheck** | Bug bounty tools | `pip install bountycheck` |
| 4 | **subjack** | Subdomain takeover | `go install github.com/haccer/subjack@latest` |
| 5 | **nuclei-templates** | Vuln templates | `git clone https://github.com/projectdiscovery/nuclei-templates` |

## 🔧 Utilities (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **curl** | HTTP client | Built-in |
| 2 | **wget** | Downloader | Built-in |
| 3 | **jq** | JSON processing | `apt install jq` |
| 4 | **git** | Version control | Built-in |
| 5 | **python3** | Scripting | Built-in |
| 6 | **pip** | Package manager | Built-in |
| 7 | **scrapling** | Anti-bot bypass | `pipx install scrapling` |
| 8 | **xurl** | URL manipulation | `go install github.com/lestrrat-go/xurl@latest` |
| 9 | **qsreplace** | Query string | `go install github.com/tomnomnom/qsreplace@latest` |
| 10 | **unfurl** | URL parsing | `go install github.com/tomnomnom/unfurl@latest` |
| 11 | **anew** | Add new lines | `go install github.com/tomnomnom/anew@latest` |
| 12 | **gron** | JSON parsing | `go install github.com/tomnomnom/gron@latest` |
| 13 | **httprobe** | HTTP probe | `go install github.com/tomnomnom/httprobe@latest` |
| 14 | **httpx** | HTTP toolkit | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| 15 | **notify** | Webhook notifications | `go install github.com/projectdiscovery/notify/cmd/notify@latest` |

## Integrated scanner registry (by group)

These are the scanners the deterministic pipeline / assessment planner drives
directly, organized into the groups shown in **New Assessment**. Each has a
scoped adapter, tolerant result parsing, and explicit coverage/failure states.
Optional scanners are off unless selected; availability reflects whether the
tool binary (and any required credential) is present.

| Group | Scanners |
|---|---|
| **Web & API** | subfinder, httpx, katana, nuclei, zap, testssl, nikto*, dalfox*, wapiti*, sqlmap* |
| **Network & servers** | nmap, masscan*, openvas, vuls, lynis* |
| **Cloud** | prowler*, scoutsuite* |
| **Kubernetes** | kube-bench* |
| **Source, dependencies & containers** | trivy, semgrep, gitleaks, osv |

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

## Summary

| Category | Count |
|----------|-------|
| Recon & Subdomain | 15 |
| HTTP & Scanning | 15 |
| Exploitation | 15 |
| Information Gathering | 10 |
| Security Scanning | 10 |
| WAF & Protection | 5 |
| Utilities | 15 |
| **TOTAL** | **85+** |

Xalgorix bundles this catalog of security tools, which the deterministic scanner pipeline drives in a fixed order.

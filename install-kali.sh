#!/usr/bin/env bash
#
# install-kali.sh — native (no-Docker) install of Pent Tool on Kali / Debian.
#
# Run it from the repository root on the Kali box:
#   git clone https://github.com/acho2003/pent-tool.git
#   cd pent-tool
#   ./install-kali.sh
#
# What it does:
#   1. Ensures Go 1.26+ (installs go1.26.5 to /usr/local/go if yours is older).
#   2. Builds the self-contained xalgorix binary (UI is embedded; no Node needed).
#   3. Installs the scanner tools it drives (apt first, go/pipx fallback).
#      Missing tools are fine — they just show as "unavailable" in the UI.
#   4. Creates ~/.xalgorix/data, a 32-byte credential-vault key, and an env file.
#
# It installs NO LLM/AI, NO Greenbone/OpenVAS and NO ZAP by default — those are
# optional heavy services (see the notes printed at the end).
#
set -euo pipefail

GO_VERSION="1.26.5"
PREFIX="${PREFIX:-/usr/local/bin}"
DATA_DIR="${XALGORIX_DATA_DIR:-$HOME/.xalgorix/data}"
KEY_FILE="${XALGORIX_CREDENTIAL_KEY_FILE:-$HOME/.xalgorix/credential.key}"
ENV_FILE="${ENV_FILE:-$HOME/.xalgorix.env}"
GOBIN_DIR="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${CYAN}==>${NC} $*"; }
ok()   { echo -e "${GREEN} ok${NC} $*"; }
warn() { echo -e "${YELLOW}  ~ ${NC}$*" >&2; }
die()  { echo -e "${RED}error:${NC} $*" >&2; exit 1; }

[ -d cmd/xalgorix ] || die "run this from the pent-tool repository root (cmd/xalgorix not found)."
command -v apt-get >/dev/null 2>&1 || die "this script targets Debian/Kali (apt-get not found)."

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ── 1. Go toolchain ──────────────────────────────────────────────────────────
need_go() {
  command -v go >/dev/null 2>&1 || return 0
  local have; have="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  [ "$(printf '%s\n%s\n' "1.26" "$have" | sort -V | head -1)" != "1.26" ]
}
if need_go; then
  info "Installing Go ${GO_VERSION} to /usr/local/go"
  case "$(uname -m)" in
    x86_64|amd64) garch=amd64 ;;
    aarch64|arm64) garch=arm64 ;;
    *) die "unsupported arch $(uname -m) for the Go tarball; install Go 1.26+ manually." ;;
  esac
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -fSL "https://go.dev/dl/go${GO_VERSION}.linux-${garch}.tar.gz" -o "$tmp/go.tgz"
  $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf "$tmp/go.tgz"
  export PATH="/usr/local/go/bin:$PATH"
fi
ok "Go: $(go version)"

# ── 2. Build the binary (embedded UI, no cgo) ────────────────────────────────
info "Building xalgorix"
REV="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
CGO_ENABLED=0 go build \
  -ldflags "-s -w -X github.com/xalgord/xalgorix/v4/internal/scanner.BuildRevision=$REV" \
  -o ./xalgorix ./cmd/xalgorix
$SUDO install -m 0755 ./xalgorix "$PREFIX/xalgorix"
ok "Installed $PREFIX/xalgorix ($("$PREFIX/xalgorix" --version 2>/dev/null | head -1 || echo built))"

# ── 3. Scanner tools ─────────────────────────────────────────────────────────
info "Installing scanner tools (best effort; skips what is already present)"
$SUDO apt-get update -qq || warn "apt-get update failed; continuing"

# Available in the Kali repositories.
APT_TOOLS=(nmap masscan nikto wapiti sslyze chromium git openssl curl ca-certificates
           nuclei subfinder httpx-toolkit katana dnsx dalfox trivy gitleaks pipx)
for pkg in "${APT_TOOLS[@]}"; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then ok "apt: $pkg (present)"; continue; fi
  if $SUDO apt-get install -y -qq "$pkg" >/dev/null 2>&1; then ok "apt: $pkg"; else warn "apt: $pkg unavailable (will try fallback / mark optional)"; fi
done

# Go-install fallback for tools not packaged or not installed above.
goinstall() { # goinstall <binary> <module@version>
  command -v "$1" >/dev/null 2>&1 && { ok "go: $1 (present)"; return; }
  info "go install $2"
  if GOBIN="$GOBIN_DIR" go install "$2" >/dev/null 2>&1; then ok "go: $1 -> $GOBIN_DIR"; else warn "go: $1 failed"; fi
}
goinstall httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
goinstall subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
goinstall dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx@latest
goinstall katana       github.com/projectdiscovery/katana/cmd/katana@latest
goinstall nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
goinstall dalfox       github.com/hahwul/dalfox/v2@latest
goinstall gau          github.com/lc/gau/v2/cmd/gau@latest
goinstall waybackurls  github.com/tomnomnom/waybackurls@latest
goinstall osv-scanner  github.com/google/osv-scanner/cmd/osv-scanner@latest

# Python tools (optional: source / cloud assessments).
if command -v pipx >/dev/null 2>&1; then
  pipx ensurepath >/dev/null 2>&1 || true
  for t in semgrep scoutsuite prowler; do
    command -v "$t" >/dev/null 2>&1 && { ok "pipx: $t (present)"; continue; }
    if pipx install "$t" >/dev/null 2>&1; then ok "pipx: $t"; else warn "pipx: $t failed (optional)"; fi
  done
else
  warn "pipx missing: semgrep/scoutsuite/prowler not installed (optional)"
fi

# testssl.sh is not an apt package by that command name; clone it if absent.
if ! command -v testssl.sh >/dev/null 2>&1; then
  if [ ! -x /opt/testssl.sh/testssl.sh ]; then
    $SUDO git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh >/dev/null 2>&1 \
      && ok "testssl.sh -> /opt/testssl.sh/testssl.sh (set XALGORIX_TESTSSL_PATH)" \
      || warn "testssl.sh clone failed (optional)"
  fi
fi

# ── 4. Runtime setup: data dir, vault key, env file ──────────────────────────
info "Configuring runtime"
mkdir -p "$DATA_DIR" "$(dirname "$KEY_FILE")"
chmod 700 "$(dirname "$DATA_DIR")" 2>/dev/null || true
if [ ! -s "$KEY_FILE" ]; then
  openssl rand -out "$KEY_FILE" 32 && chmod 600 "$KEY_FILE"
  ok "Credential vault key -> $KEY_FILE"
else
  ok "Credential vault key already present"
fi

if [ ! -f "$ENV_FILE" ]; then
  GEN_PW="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)"
  cat > "$ENV_FILE" <<EOF
# Pent Tool runtime environment. Source it before launching: set -a; . ~/.xalgorix.env; set +a
export PATH="/usr/local/go/bin:$GOBIN_DIR:\$PATH"
export XALGORIX_DATA_DIR="$DATA_DIR"
export XALGORIX_CREDENTIAL_KEY_FILE="$KEY_FILE"
export XALGORIX_USERNAME="admin"
export XALGORIX_PASSWORD="$GEN_PW"
# Scan localhost/lab targets (the dashboard's own port stays protected):
export XALGORIX_ALLOW_LOCAL_TARGETS="true"
# testssl.sh if cloned to /opt:
[ -x /opt/testssl.sh/testssl.sh ] && export XALGORIX_TESTSSL_PATH="/opt/testssl.sh/testssl.sh"
# Optional external ZAP daemon:
# export XALGORIX_ZAP_URL="http://127.0.0.1:8080"
# export XALGORIX_ZAP_API_KEY="change-me"
EOF
  chmod 600 "$ENV_FILE"
  ok "Env file -> $ENV_FILE  (login: admin / $GEN_PW)"
else
  ok "Env file already present: $ENV_FILE (left unchanged)"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo
echo -e "${GREEN}Install complete.${NC} Start the dashboard:"
echo
echo "    set -a; . \"$ENV_FILE\"; set +a"
echo "    xalgorix --web"
echo
echo "  Then open http://127.0.0.1:9137"
echo
echo "  Optional heavy services (not installed by this script):"
echo "   - ZAP:        sudo apt install zaproxy; run as daemon; set XALGORIX_ZAP_URL + XALGORIX_ZAP_API_KEY"
echo "   - Greenbone:  sudo apt install gvm && sudo gvm-setup; set XALGORIX_GVM_SOCKET or XALGORIX_GVM_HOST"
echo
echo "  Check which tools the app sees: the New Scan page marks any missing tool 'unavailable'."

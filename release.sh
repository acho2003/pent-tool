#!/usr/bin/env bash
set -euo pipefail

# ─── Xalgorix Release Script ───
# Usage:
#   ./release.sh                  # auto-bump patch (4.2.10 → 4.2.11)
#   ./release.sh 4.3.0            # explicit version
#   ./release.sh --minor          # bump minor (4.2.10 → 4.3.0)
#   ./release.sh --major          # bump major (4.2.10 → 5.0.0)

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
MAIN_GO="$REPO_ROOT/cmd/xalgorix/main.go"
BUILD_DIR="/tmp/xalgorix-release"

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[•]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ─── Pre-flight checks ───
command -v go >/dev/null  || die "go not found"
command -v gh >/dev/null  || die "gh CLI not found (install: https://cli.github.com)"
command -v git >/dev/null || die "git not found"

cd "$REPO_ROOT"

# Ensure clean working tree
if [[ -n "$(git status --porcelain)" ]]; then
    die "Working tree is dirty. Commit or stash changes first."
fi

# ─── Determine current version ───
CURRENT=$(grep -oP 'var version = "\K[^"]+' "$MAIN_GO")
[[ -z "$CURRENT" ]] && die "Could not parse current version from $MAIN_GO"

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
info "Current version: ${CYAN}v$CURRENT${NC}"

# ─── Determine new version ───
if [[ $# -eq 0 ]]; then
    # Auto-bump patch
    NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
elif [[ "$1" == "--minor" ]]; then
    NEW_VERSION="$MAJOR.$((MINOR + 1)).0"
elif [[ "$1" == "--major" ]]; then
    NEW_VERSION="$((MAJOR + 1)).0.0"
elif [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    NEW_VERSION="$1"
else
    die "Invalid argument: $1\nUsage: $0 [version|--minor|--major]"
fi

info "New version:     ${GREEN}v$NEW_VERSION${NC}"
echo ""

# ─── Confirm ───
read -rp "Proceed with release v$NEW_VERSION? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; exit 0; }
echo ""

# ─── Step 1: Bump version in source ───
info "Bumping version in main.go..."
sed -i "s/var version = \"$CURRENT\"/var version = \"$NEW_VERSION\"/" "$MAIN_GO"
ok "Version bumped: $CURRENT → $NEW_VERSION"

# ─── Step 2: Build & verify ───
info "Building and verifying..."
# The previous version had `die` before `git checkout`, but `die` calls
# `exit 1` so the checkout never ran and the version bump was left on disk.
# Reorder: revert the bump first, then exit.
if ! go build ./cmd/xalgorix/; then
    warn "Build failed — reverting version bump in $MAIN_GO"
    git checkout -- "$MAIN_GO"
    die "Build failed (version bump reverted)"
fi
ok "Build successful"

# ─── Step 3: Build release binary ───
info "Building linux/amd64 release binary..."
mkdir -p "$BUILD_DIR"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.version=$NEW_VERSION" \
    -o "$BUILD_DIR/xalgorix-linux-amd64" \
    ./cmd/xalgorix/
ok "Binary built: $BUILD_DIR/xalgorix-linux-amd64"

# ─── Step 4: Generate changelog ───
info "Generating changelog..."
CHANGELOG=$(git log --oneline "v$CURRENT"..HEAD 2>/dev/null | sed 's/^/- /' || echo "- Release v$NEW_VERSION")
if [[ -z "$CHANGELOG" ]]; then
    CHANGELOG="- Release v$NEW_VERSION"
fi
echo "$CHANGELOG"
echo ""

# ─── Step 5: Commit & tag ───
info "Committing and tagging..."
git add -A
git commit -m "release: v$NEW_VERSION"
git tag "v$NEW_VERSION"
ok "Tagged v$NEW_VERSION"

# ─── Step 6: Push ───
info "Pushing to origin..."
git push origin main
git push origin "v$NEW_VERSION"
ok "Pushed to origin"

# ─── Step 7: Create GitHub Release ───
info "Creating GitHub Release..."
gh release create "v$NEW_VERSION" \
    "$BUILD_DIR/xalgorix-linux-amd64" \
    --title "v$NEW_VERSION" \
    --notes "### Changes

$CHANGELOG"
ok "GitHub Release created"

# ─── Cleanup ───
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✅ Released v$NEW_VERSION successfully!${NC}"
echo -e "${GREEN}  https://github.com/xalgord/xalgorix/releases/tag/v$NEW_VERSION${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

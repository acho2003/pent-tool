#!/usr/bin/env bash
# scripts/migrate_skills.sh
#
# One-shot migration: replace the existing tools/skills/data tree with
# skills from mukul975/Anthropic-Cybersecurity-Skills, organized by
# `subdomain` -> data/<category>/<skill-name>/SKILL.md.
#
# Preserves data/reconnaissance/ (per user request), and the agent-internal
# data/coordination/, data/scan_modes/, data/custom/ folders + README.md.

set -euo pipefail

SOURCE="${1:-/tmp/acs}"
DEST="/vercel/share/v0-project/internal/tools/skills/data"

if [[ ! -d "$SOURCE/skills" ]]; then
  echo "Missing $SOURCE/skills" >&2
  exit 1
fi

# Wipe categories that ACS replaces; keep recon, coord, scan_modes, custom.
for cat in cloud frameworks protocols technologies vulnerabilities; do
  rm -rf "$DEST/$cat"
done

# Normalize subdomain spellings to a single canonical category name.
canonicalize() {
  case "$1" in
    "red-team") echo "red-teaming" ;;
    "ot-security") echo "ot-ics-security" ;;
    "zero-trust") echo "zero-trust-architecture" ;;
    "identity-and-access-management"|"identity-security") echo "identity-access-management" ;;
    *) echo "$1" ;;
  esac
}

# Extract `subdomain:` from YAML frontmatter (single-line value).
read_subdomain() {
  awk '
    BEGIN { in_fm = 0 }
    /^---[[:space:]]*$/ {
      in_fm = !in_fm
      if (!in_fm) exit
      next
    }
    in_fm && /^subdomain:/ {
      sub(/^subdomain:[[:space:]]*/, "")
      gsub(/^["'\'']|["'\'']$/, "")
      print
      exit
    }
  ' "$1"
}

count=0
skipped=0
for dir in "$SOURCE"/skills/*/; do
  skill_name="$(basename "$dir")"
  skill_md="$dir/SKILL.md"
  if [[ ! -f "$skill_md" ]]; then
    skipped=$((skipped + 1))
    continue
  fi
  sub="$(read_subdomain "$skill_md" || true)"
  if [[ -z "$sub" ]]; then
    sub="general"
  fi
  cat="$(canonicalize "$sub")"
  # Keep the user's reconnaissance category isolated; ACS has none, but guard.
  if [[ "$cat" == "reconnaissance" ]]; then
    cat="recon-acs"
  fi
  target_dir="$DEST/$cat/$skill_name"
  mkdir -p "$target_dir"
  cp "$skill_md" "$target_dir/SKILL.md"
  count=$((count + 1))
done

echo "Migrated $count skills (skipped $skipped without SKILL.md)."
echo "Categories now in $DEST:"
ls -1 "$DEST"

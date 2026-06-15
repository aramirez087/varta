#!/usr/bin/env bash
#
# find-users.sh — find repos that already IMPORT a Varta client in any of the
# 6 official languages. These are real users (higher intent than a stargazer):
# someone wrote `use varta_client` / `import varta` in their own code.
#
# Output: CSV of distinct repos + the owner's profile, noise filtered out.
#
# Requires: gh (authed), jq.
# Usage:
#   ./marketing/find-users.sh                 # prints CSV to stdout
#   ./marketing/find-users.sh > marketing/users.csv
#
set -euo pipefail

OUT="${1:-/dev/stdout}"
command -v gh >/dev/null || { echo "need gh CLI" >&2; exit 1; }
command -v jq >/dev/null || { echo "need jq" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "run: gh auth login" >&2; exit 1; }

# Per-language import signatures. Most-specific token wins (less noise than the
# bare package name, which only hits registry mirrors).
#   "label::query"
# NB: bare "varta" is a battery brand (VARTA) + a Hindi word + a surname —
# pure noise. Every signature below is API-unique to THIS library.
PATTERNS=(
  "rust::use varta_client"
  "python::from varta import Varta"
  "python::Varta.connect"
  "go::aramirez087/Varta/clients/go"
  "node::@varta-health/client"
  "dotnet::using Varta.Client"
  "jvm::import health.varta"
)

# Repos to drop: own repos, registry mirrors, obvious name-collisions.
NOISE='^(aramirez087/[Vv]arta|.*/crates\.io-index|.*/homebrew-.*|.*-index$|vortexfr/Vartacraft.*)$'

echo "searching code for Varta imports across 6 languages ..." >&2

tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT

for entry in "${PATTERNS[@]}"; do
  label="${entry%%::*}"; q="${entry#*::}"
  echo "  [$label] $q" >&2
  # --limit caps at 100/query; quote the phrase so it's matched literally-ish.
  gh search code "$q" --limit 100 --json repository \
      -q '.[].repository.nameWithOwner' 2>/dev/null \
    | sed "s|\$| $label|" >> "$tmp" || true
  sleep 1   # code-search is rate-limited harder than REST
done

# Collapse: one row per repo, with the set of languages that matched.
# (macOS ships bash 3.2 — no `declare -A`, so aggregate in awk instead.)
# Input lines: "repo label". Output lines: "repo<TAB>lang1 lang2 ...".
collapsed="$(grep -Ev "$NOISE" "$tmp" 2>/dev/null \
  | awk 'NF>=2 { r=$1; l=$2; if(!((r SUBSEP l) in seen)){seen[r,l]=1; langs[r]=(langs[r]?langs[r]" "l:l)} }
         END { for(r in langs) print r"\t"langs[r] }' \
  | sort)"

n="$(printf '%s\n' "$collapsed" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "found $n candidate user-repos (noise filtered). enriching owners ..." >&2

csv() { printf '%s' "$1" | sed 's/"/""/g' | awk '{print "\""$0"\""}'; }

{
echo "repo,languages,stars,owner,owner_name,owner_company,owner_location,owner_email,repo_url"
printf '%s\n' "$collapsed" | while IFS=$'\t' read -r repo langs; do
  [ -z "${repo:-}" ] && continue
  owner="${repo%%/*}"
  r="$(gh api "/repos/$repo" 2>/dev/null || true)"
  stars="$(jq -r '.stargazers_count // 0' <<<"$r" 2>/dev/null || echo 0)"
  rurl="$(jq -r '.html_url // ""'        <<<"$r" 2>/dev/null || echo "")"
  u="$(gh api "/users/$owner" 2>/dev/null || true)"
  oname="$(jq -r '.name // ""'     <<<"$u" 2>/dev/null || echo "")"
  ocomp="$(jq -r '.company // ""'  <<<"$u" 2>/dev/null || echo "")"
  oloc="$(jq -r '.location // ""'  <<<"$u" 2>/dev/null || echo "")"
  omail="$(jq -r '.email // ""'    <<<"$u" 2>/dev/null || echo "")"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv "$repo")" "$(csv "$langs")" "$stars" \
    "$owner" "$(csv "$oname")" "$(csv "$ocomp")" "$(csv "$oloc")" \
    "$(csv "$omail")" "$rurl"
  sleep 0.3
done
} > "$OUT"

echo "done -> $OUT" >&2
echo "these people WROTE Varta into their code — best interview targets. DM them first." >&2

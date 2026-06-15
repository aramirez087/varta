#!/usr/bin/env bash
#
# pull-leads.sh — mine Varta's GitHub stargazers + forkers into a ranked
# interview-lead CSV. Each lead is enriched with profile data and scored by
# how likely they are to run a fleet of long-running agents (the Varta ICP).
#
# Requires: gh (authed), jq.
# Usage:
#   ./marketing/pull-leads.sh                 # defaults to aramirez087/Varta
#   REPO=owner/name ./marketing/pull-leads.sh
#   ./marketing/pull-leads.sh > marketing/leads.csv
#
set -euo pipefail

REPO="${REPO:-aramirez087/Varta}"
OUT="${1:-/dev/stdout}"

command -v gh >/dev/null || { echo "need gh CLI" >&2; exit 1; }
command -v jq >/dev/null || { echo "need jq" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "run: gh auth login" >&2; exit 1; }

echo "pulling stargazers + forkers for $REPO ..." >&2

# 1. Collect unique logins from stargazers and forkers.
#    --paginate walks every page; jq pulls the login field.
stargazers="$(gh api --paginate "/repos/$REPO/stargazers" -q '.[].login' 2>/dev/null || true)"
forkers="$(gh api --paginate "/repos/$REPO/forks" -q '.[].owner.login' 2>/dev/null || true)"

logins="$(printf '%s\n%s\n' "$stargazers" "$forkers" | sort -u | sed '/^$/d')"
count="$(printf '%s\n' "$logins" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "found $count unique people. enriching profiles ..." >&2

if [ "$count" = "0" ]; then
  echo "no stargazers/forkers yet — nothing to pull." >&2
  exit 0
fi

# 2. ICP keyword regex — bumps score when bio/company hints at the buyer.
ICP='agent|robot|drone|edge|iot|fleet|daemon|infra|platform|sre|devops|embedded|autonom|swarm|kubernetes|distributed|reliab|observability'

# 3. CSV header.
{
echo "score,login,name,company,location,followers,public_repos,blog,twitter,email,signal,profile_url"

# 4. Enrich each login. Sleep 0.3s to stay polite to the API.
printf '%s\n' "$logins" | while IFS= read -r login; do
  [ -z "$login" ] && continue
  u="$(gh api "/users/$login" 2>/dev/null || true)"
  [ -z "$u" ] && continue

  name="$(jq -r '.name // ""'        <<<"$u")"
  company="$(jq -r '.company // ""'  <<<"$u")"
  loc="$(jq -r '.location // ""'     <<<"$u")"
  followers="$(jq -r '.followers // 0' <<<"$u")"
  repos="$(jq -r '.public_repos // 0'  <<<"$u")"
  blog="$(jq -r '.blog // ""'        <<<"$u")"
  tw="$(jq -r '.twitter_username // ""' <<<"$u")"
  email="$(jq -r '.email // ""'      <<<"$u")"
  bio="$(jq -r '.bio // ""'          <<<"$u")"
  url="$(jq -r '.html_url // ""'     <<<"$u")"

  # Heuristic score: ICP keyword hit (+3), has company (+2), has email (+2),
  # >100 followers (+1). Higher = interview first.
  score=0
  hay="$(printf '%s %s %s' "$bio" "$company" "$loc" | tr 'A-Z' 'a-z')"
  signal=""
  if printf '%s' "$hay" | grep -Eq "$ICP"; then
    score=$((score+3)); signal="icp-keyword"
  fi
  [ -n "$company" ] && score=$((score+2))
  [ -n "$email" ]   && { score=$((score+2)); signal="${signal:+$signal,}has-email"; }
  [ "$followers" -gt 100 ] 2>/dev/null && score=$((score+1))

  # CSV-escape: wrap fields with commas/quotes, double internal quotes.
  csv() { printf '%s' "$1" | sed 's/"/""/g' | awk '{print "\""$0"\""}'; }

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$score" "$login" \
    "$(csv "$name")" "$(csv "$company")" "$(csv "$loc")" \
    "$followers" "$repos" "$(csv "$blog")" "$tw" \
    "$(csv "$email")" "$(csv "$signal")" "$url"

  sleep 0.3
done | sort -t, -k1,1 -nr   # rank by score, highest first
} > "$OUT"

echo "done -> $OUT" >&2
echo "next: open in a sheet, DM the top scorers first (see outreach script in §07)." >&2

#!/usr/bin/env bash
# Collect every repo's .github/security-exceptions.yml (lesson 3.4 format) into one register.
# Status per entry: OK, SOON (expires within WARN_DAYS), EXPIRED, INVALID (a field missing,
# a bad date, or more than 90 days away). Each entry also shows the commit that last changed
# the file, so you can find the PR that approved it.
# Prints a markdown table, writes register.json, exits 1 if anything is EXPIRED or INVALID.
# Needs gh, jq and yq v4 (on GitHub's Ubuntu runners; locally: YQ="docker run --rm -i mikefarah/yq:4.54.1").
#
#   ORG=<your-test-org> ./exceptions-register.sh
#   ORG=<your-test-org> TODAY=2027-01-10 ./exceptions-register.sh   # what it will look like then
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
WARN_DAYS="${WARN_DAYS:-14}"
TODAY="${TODAY:-$(date -u +%F)}"
YQ="${YQ:-yq}"
OUT="${OUT:-register.json}"
FILE=.github/security-exceptions.yml
# Without yq every file would parse to nothing and the register would look clean.
$YQ --version >/dev/null 2>&1 || { echo "yq not found (set YQ=...)" >&2; exit 2; }

entries=()
while read -r r; do
  raw=$(gh api "repos/$ORG/$r/contents/$FILE" --jq .content 2>/dev/null | base64 -d 2>/dev/null) || continue
  [[ -z "$raw" ]] && continue
  last=$(gh api "repos/$ORG/$r/commits?path=$FILE&per_page=1" --jq '.[0] | "\(.sha[:7]) \(.commit.committer.date[:10])"')
  while read -r e; do entries+=("$e"); done < <($YQ -o=json -I=0 '.exceptions // [] | .[]' <<<"$raw" \
    | jq -c --arg repo "$r" --arg last "$last" '. + {repo: $repo, last_change: $last}')
done < <(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[] | select(.archived | not) | .name')

printf '%s\n' "${entries[@]}" | jq -s --arg today "$TODAY" --argjson warn "$WARN_DAYS" '
  def day: strptime("%Y-%m-%d") | mktime;
  map(select(. != null)) | map(
    (try (((.expires | tostring | day) - ($today | day)) / 86400) catch null) as $left
    | . + {days_left: $left, status:
        (if ([.id, .rule, .path, .reason, .owner, .expires] | any(. == null or . == "")) or $left == null or $left > 90 then "INVALID"
         elif $left < 0 then "EXPIRED"
         elif $left <= $warn then "SOON"
         else "OK" end)})
  | sort_by(.days_left // -9999)' > "$OUT"

echo "Exception register for $ORG on $TODAY ($(jq length "$OUT") entries)"
echo
echo "| Status | Repo | Id | Rule | Path | Owner | Expires | Days left | Last change | Reason |"
echo "|---|---|---|---|---|---|---|---|---|---|"
jq -r '.[] | "| \(.status) | \(.repo) | \(.id) | \(.rule) | \(.path) | \(.owner) | \(.expires) | \(.days_left) | \(.last_change) | \(.reason) |"' "$OUT"
echo
jq -r 'group_by(.status) | map("\(.[0].status): \(length)") | join(", ")' "$OUT"
[[ $(jq '[.[] | select(.status == "EXPIRED" or .status == "INVALID")] | length' "$OUT") == 0 ]]

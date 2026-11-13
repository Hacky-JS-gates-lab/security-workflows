#!/usr/bin/env bash
# List every ruleset bypass in every repo: when, who, which PR, which rules it skipped, and
# whether the PR has a comment starting with "Bypass:" that gives the reason (bypass-policy.md).
# Reads the rule insights API (GET /repos/{o}/{r}/rulesets/rule-suites), which works on Free
# for repo rulesets. It only looks back one month (time_period hour|day|week|month), so save
# the output weekly if you need a longer history.
# Prints a table, writes bypasses.json, exits 1 if any bypass has no reason.
#
#   ORG=<your-test-org> ./bypasses.sh                 # last month
#   ORG=<your-test-org> PERIOD=week ./bypasses.sh     # for the weekly review
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
PERIOD="${PERIOD:-month}"
OUT="${OUT:-bypasses.json}"

rows=()
while read -r r; do
  while read -r s; do
    [[ -z "$s" ]] && continue
    id=$(jq -r .id <<<"$s"); sha=$(jq -r .after_sha <<<"$s")
    # What was bypassed: the rules that failed in this rule suite.
    skipped=$(gh api "repos/$ORG/$r/rulesets/rule-suites/$id" \
      --jq '[.rule_evaluations[] | select(.result == "fail") | .rule_type + (if .details then ": " + .details else "" end)]')
    pr=$(gh api "repos/$ORG/$r/commits/$sha/pulls" --jq '.[0].number // empty' 2>/dev/null || true)
    reason=null
    if [[ -n "$pr" ]]; then
      reason=$(gh api --paginate "repos/$ORG/$r/issues/$pr/comments" \
        --jq '.[] | select(.body | test("^\\s*bypass:"; "i")) | .body' | head -1 | jq -R . | jq -s '.[0]')
    fi
    rows+=("$(jq -c --arg repo "$r" --arg pr "$pr" --argjson skipped "$skipped" --argjson reason "$reason" \
      '{repo: $repo, at: .pushed_at, actor: .actor_name, pr: (if $pr == "" then null else ($pr | tonumber) end),
        skipped: $skipped, reason: $reason}' <<<"$s")")
  done < <(gh api --paginate "repos/$ORG/$r/rulesets/rule-suites?time_period=$PERIOD&rule_suite_result=bypass&per_page=100" \
             --jq '.[] | @json')
done < <(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[] | select(.archived | not) | .name')

printf '%s\n' "${rows[@]}" | jq -s 'map(select(. != null)) | sort_by(.at) | reverse' > "$OUT"

jq -r '["WHEN","REPO","ACTOR","PR","REASON","SKIPPED"],
  (.[] | [.at[:16], .repo, .actor, (.pr // "-" | tostring), (if .reason then "yes" else "NONE" end),
          (if .skipped == [] then "(nothing failed)" else (.skipped | join("; ") | .[:90]) end)]) | @tsv' "$OUT" \
  | column -t -s $'\t'
echo
echo "$(jq length "$OUT") bypasses in the last $PERIOD; without a reason: $(jq '[.[] | select(.reason == null)] | length' "$OUT")"
jq -r 'group_by(.repo) | map("  \(.[0].repo): \(length)") | .[]' "$OUT"
[[ $(jq '[.[] | select(.reason == null)] | length' "$OUT") == 0 ]]

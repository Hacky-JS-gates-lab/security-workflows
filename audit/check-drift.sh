#!/usr/bin/env bash
# Compare each repo's copy of a ruleset with the file it came from.
# Prints OK, MISSING or CHANGED per repo and exits 1 if anything drifted.
# FIX=1 puts the file's version back on the drifted repos (with apply-baseline.sh).
#
#   ORG=<your-test-org> ./check-drift.sh [baseline.json]
#   ORG=<your-test-org> FIX=1 ./check-drift.sh [baseline.json]
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FILE="${1:-$HERE/baseline.json}"
NAME=$(jq -er .name "$FILE")

# Only the fields that define behaviour; ids, timestamps and links are dropped.
NORM='{name, target, enforcement,
  bypass_actors: ((.bypass_actors // []) | sort_by(.actor_type, .actor_id)),
  conditions: (.conditions | .ref_name.include |= sort | .ref_name.exclude |= sort),
  rules: (.rules | sort_by(.type))}'
want=$(jq -S "$NORM" "$FILE")

drifted=()
while read -r r; do
  id=$(gh api "repos/$ORG/$r/rulesets?includes_parents=false&per_page=100" \
    | jq -r --arg n "$NAME" '.[] | select(.name == $n) | .id')
  if [[ -z "$id" ]]; then
    echo "MISSING  $r"; drifted+=("$r"); continue
  fi
  got=$(gh api "repos/$ORG/$r/rulesets/$id" | jq -S "$NORM")
  if [[ "$got" == "$want" ]]; then
    echo "OK       $r"
  else
    echo "CHANGED  $r"
    diff <(echo "$want") <(echo "$got") | grep '^[<>]' | sed 's/^</    want/; s/^>/    got /' | head -8 || true
    drifted+=("$r")
  fi
done < <(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[] | select(.archived | not) | .name')

[[ ${#drifted[@]} -eq 0 ]] && exit 0
if [[ "${FIX:-0}" == 1 ]]; then
  "$HERE/apply-baseline.sh" "$FILE" "${drifted[@]}"
fi
exit 1
